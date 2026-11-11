# R3 pre-registration: a document-level decision for the long path (RF-895d3533, todo R3)

Written on 2026-11-11, before any candidate below was fitted or measured, before any embedded-attack
document was scored, and before any holdout evaluation. `train/longdoc_r3.py` implements every
definition here; its constants are the values below. Committed with this file.

## Problem

On the bench/long `long` profile (128 benign documents of 100k and 200k tokens, 66 dev / 62 holdout;
`docs/benchmark.md`, "Long documents"), v6 with its cap 0.88 blocks 17 / 66 dev and 15 / 62 holdout
documents at 0.85 (R2b). A document is blocked by its single worst unit among hundreds; the share of
units at or above 0.85 is at most 0.4% in every genre. Target (todo R3 acceptance): document-level
false-positive rate at most 1% at 100k and at 200k tokens, and detection of attacks embedded in long
documents at least the stand-alone detection of the same payloads minus 5 points, every byte scored, no
sampling.

## Disclosure

The holdout benign documents' decisions at the fixed 0.85 threshold were seen in R2b (15 / 62 blocked,
measured on 2,048-byte fused chunks). The holdout half of the embedded-attack corpus below has never been
scored. Nothing in this plan was tuned on either. Seen on dev before this file: a smoke test of the new
`cmd/benchlong -long on` path on four dev Wikipedia documents of 100k tokens (largest window 0.757,
0.748, 0.100 and 0.035; none blocked), to check the dump; the full dev and holdout benign runs had
started when this file was written, and none of their scores had been read.

## The unit: the gateway's long path

A document of 100k tokens reaches the gateway's long path (`MAX_SCAN_TOKENS`; more than 128 KiB of
untrusted text): `ml.ScoreLong` cuts it into the classifier's 256-token windows (64-token overlap, a new
window every 190 tokens), fuses each window from L1 on its text and L2 on its tokens with the `l1,l2`
logistic regression (L3 does not run there), applies the gateway's adjustment for documents (the
classifier's cap for untrusted content, `l2_untrusted_max` 0.88, then code corroboration, on by default),
and the document's score is its largest window. R2b measured `cmd/benchlong`'s fused 2,048-byte chunks,
the short path's unit, so R3 measures the windows the gateway actually decides on:
`cmd/benchlong -long on` runs `ml.ScoreLong` itself with `KeepWindows` and `-dump` writes every window's
score, calibrated L1 and L2, floor and whether L1 corroborates it (scores only, no text). Model:
`guardspec-classifier-v6` (package `guardspec-data/v6/release/guardspec-classifier-v6`, its
`calibration.json`).

## Data

- **Benign**: the `long` profile, scored once with `-long on -l2pass off -layers none` (the dump writes
  dev and holdout to separate files). Documents the sanitizer rejects are not scored and not counted in
  the model rates (as in R2b). Size label from the corpus token count (100k, 200k).
- **Attacks**: `bench/long/embed_long.py` (committed with this file). Payloads: the `control` documents
  of the `full` profile (attack rows of the eval/ dev half; bench split by payload id: 32 dev, 15 EN /
  17 VI, and 32 holdout, 17 EN / 15 VI). Each payload is scored alone (`control`) and embedded in a long
  benign document of its own language and bench split in seven variants (the v6 gate G7 set):
  `pos_start`, `pos_end`, `pos_random`, `straddle_window` (across the end of a random long-path window),
  `straddle_chunk`, `straddle_segment`, `split_adjacent`; host drawn with a seeded generator
  (seed 20261111) per payload and variant. Hosts left out (`exclude-hosts.txt`): the two documents the
  sanitizer rejects (`long-docs-vi-100000-0`, `-1`) and the two it cuts to under 15% of their length
  (`long-docs-en-200000-3`, `long-rfc-en-200000-3`). An attack document whose payload is not found whole in
  the sanitized text (`intact` false in the dump) is excluded and counted. 32 × 8 = 256 documents per
  split. Dev payloads only ever sit in dev documents, holdout payloads in holdout documents; the corpus
  is new text only in its combination (both parts already pass `train/data/bench_guard.py` against the
  v6 data).
- **Detection** of a document: the rule blocks it (any window). Reported next to it: the payload's own
  windows (windows overlapping the payload's span in the sanitized text) blocking.

## Candidates

θ = 0.85 (the gateway's block threshold), α = 0.01 (target document false-positive rate). For a text of
n windows with window scores s_i and c_i = "L1 corroborates window i" (calibrated L1 at least the
calibrated value of raw 0.5, the code-corroboration bar, which every decisive rule reaches, or a floor
applied):

| id | rule for n > n0 (texts of at most n0 windows: unchanged, any s_i ≥ θ blocks) |
|---|---|
| `base` | any s_i ≥ θ (today; reference, not a candidate) |
| `corr` | any s_i ≥ θ with c_i (corroboration extended to every window of a long document) |
| `tn` | any s_i ≥ T(n) (length-aware threshold) |
| `combo` | any s_i ≥ θ with c_i, or any s_i ≥ T(n) |
| `kofn` | at least k windows with s_i ≥ θ |

## Fitting (dev benign documents only)

- Stream: the window scores of the scored dev benign documents, in corpus order, both languages pooled
  (the rule must not depend on a language guess).
- p̂ = share of stream windows with s ≥ θ; **n0** = floor(ln(1 − α) / ln(1 − p̂)): the largest n at which
  n independent windows keep the base rule within α. Every candidate leaves texts of at most n0 windows
  as today.
- **T(n)**, for n in {16, 32, 64, 128, 256, 512, 1024, 2048}: the larger of θ, the 1 − α quantile of the
  maximum over n contiguous windows (circular moving-block bootstrap of the stream, 20,000 draws, seed
  20261111) and the GEV extrapolation (Hosking L-moments on the logit of 16-window block maxima, quantile
  (1 − α)^(16/n) of a block maximum) — the definition of `cmd/benchlong`. Between grid points T is
  linear in (ln n, logit T); below 16 windows T = θ; beyond 2,048 windows the 2,048 value. Used only
  for n > n0.
- **k** (`kofn`): the smallest k in {2, 3, 4, 5, 6, 8} whose dev benign 100k + 200k blocked count is at
  most α × documents; none: the candidate fails the false-positive criterion.
- `corr` has no fitted parameter besides n0.

## Selection rule (dev slice only)

For each candidate on dev: **FPR criterion** — blocked dev benign 100k + 200k documents (EN and VI
pooled) at most α × documents (with 66 documents: none); **TPR criterion** — detection of the 224
embedded dev documents (seven variants pooled, EN and VI pooled) at least the detection of the 32 dev
payloads alone minus 0.05, both under the candidate.

1. Among candidates meeting both: the highest embedded detection; tie: fewer blocked dev benign
   documents; tie: fewer parameters (order `corr`, `kofn`, `tn`, `combo`).
2. If none meets both: among those meeting the TPR criterion, the fewest blocked dev benign documents
   (tie: higher embedded detection, then the order above). Reported as not meeting the target.
3. If none meets the TPR criterion: no rule; the gateway keeps today's decision.

## Holdout (once)

After this file and the dev result are committed, the chosen rule with its dev-fitted parameters is
applied once to the holdout benign documents and the 256 holdout attack documents (`longdoc_r3.py
holdout`), next to `base`. Reported whatever the result, with two-sided Clopper–Pearson 95% intervals:
blocked benign documents per language and size and pooled; detection alone, per variant and embedded,
per language and pooled. No parameter, candidate or criterion changes after that.

## Implementation commitment

The chosen rule's parameters go into the classifier's calibration as an optional `long_doc` object
(`calibration.json`, `ml.CalibrationFile`); a calibration without it behaves exactly as today. The
gateway's long path (`ml.ScoreLong`) and `cmd/benchlong -long on` apply it. Only the v6 package gets it
(not shipped); the shipped v3b and v5 calibrations are not changed. The short path (texts within the
16-chunk / 128 KiB limits) is not changed.
