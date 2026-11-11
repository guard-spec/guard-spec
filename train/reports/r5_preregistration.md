# R5 pre-registration: a new long-document corpus, tightened rules and a stricter long-path decision (RF-895d3533, todo R5)

Written on 2026-11-11, before any candidate below was measured on the `long5` corpus, before any `long5`
document or R5 embedded-attack document was scored, and before any holdout evaluation.
`train/longdoc_r5.py` implements every definition here; its constants are the values below. The R5 rule
set (`internal/inference/rules`, this commit) and the corpus definition (`bench/long/corpus.yaml`
profile `long5`, `bench/long/embed_long.py --eval-payloads`) are committed with this file.

## Problem and target

R3 (`r3_preregistration.md`, `r3_holdout.md`) measured the gateway's long path (`ml.ScoreLong`: 256-token
windows fused from L1 and L2 with the `l1,l2` combiner, the cap 0.88 for untrusted content, code
corroboration; a document is blocked when one window reaches 0.85) and found 13 of 61 holdout benign
documents of 100k and 200k tokens blocked. A benign window crosses 0.85 at a rate of about 2.4e-4; a
document of 500 to 1,050 windows needs about 1e-5 for a document rate of 1%. Every crossing benign
window had an L1 rule or floor behind it.

Target (todo R5): blocked benign documents at most 1% at 100k and at 200k tokens on the long path, and
detection of attacks embedded in long documents at least the stand-alone detection of the same payloads
minus 5 points, every byte scored, no sampling; no regression of eval/data or val_v3 beyond the
confidence interval of v6 as it is.

## Disclosure

- The `long` profile of bench/long (R2b, R3) is burned: its dev and holdout halves were both scored, on
  the 2,048-byte chunks (R2b) and on the long path (R3). In designing the candidates below I read, on
  **both** halves of the R3 dumps, the 36 benign windows at or above 0.85 (their L1, L2, floor and rules)
  and the text of each one around the rule match, and the calibrated L1 and L2 of the payload windows
  of the R3 embedded attacks (dev and holdout). The R5 rule changes target rule matches seen there
  (listed below). I also computed, on those R3 dumps, what the decisions `agree` and `strongX` below do
  (for example a floor gate alone: 23 to 21 of 126 R3 benign documents blocked, embedded detection 92.0%
  to 91.1%; a bar of calibrated L1 0.9: 13 of 126, detection 86.6% against 92.2% alone). None of this
  reads `long5` or the R5 attack documents.
- `long5` (below) is new text: no unit of it is in a `long`, quick or full document (other files, titles
  and repositories; for the Vietnamese laws and prose the units the `long` profile left unused). Before
  this file, the corpus was built and checked against the v6 training data (`train/data/bench_guard.py`)
  and against the `long` documents; no `long5` document was scored by any model or rule layer.
- The R5 payloads are the attack rows of the eval/ dev half that come after the 32 per language the
  `full` profile (and R3) used, in build.py's seeded order. They were never scored in bench/long; as
  eval/data dev rows they are inside the aggregate eval/data dev numbers of earlier reports.

## Corpus: `long5`

`bench/long/corpus.yaml`, profile `long5` (sources and licences there; every source is public domain or
under a licence that allows this use, never owner data):

- English: Wikipedia (another file of the 2023-11-01 dump), U.S. Code titles 16, 20, 33, 38 and 49, the
  kubelet's Go source (kubernetes v1.31.0), the Rust book and the Kubernetes blog (one `docs` pool),
  English Wikisource (another file of the dump), 53 RFCs none of which is in `long`, nginx access logs.
- Vietnamese: Wikipedia (another file of the dump), laws and prose of the Vietnamese Wikisource dump (the
  units `long` left unused).
- Synthetic genres (logs, JSON, CSV, e-mail, chat, hardneg) in both languages, seed 20261112.
- Sizes 100k and 200k tokens; per size 38 English documents (Wikipedia 8, U.S. Code 5, code 3, docs 5,
  prose 5, RFC 4, web logs 2, synthetic 6) and 37 Vietnamese (Wikipedia 23, laws 6, prose 2, synthetic 6):
  150 documents, 22.48M tokens (`outputs.long5` pins the file). Dev: 74 (EN 20 + 18, VI 18 + 18 at
  100k + 200k); holdout: 76 (EN 18 + 20, VI 19 + 19). The Vietnamese genres are fewer than the English
  ones: no further Vietnamese source with verified terms was found (below).
- Split: the eval/ convention on the document id (`long5-…`), dev and holdout in separate corpus
  directories, so a dev run never scores a holdout document.
- Units sharing a 50-token shingle with a v6 training or validation row are left out (`exclude.json`,
  `train/data/bench_guard.py`), as for `long`; the kubelet files after their Apache-2.0 licence comment is
  stripped (the comment alone matched training code in 469 of 487 files). Also left out: units of which
  20% or more of the 50-token shingles occur in a quick, full or `long` document (other Wikisource
  versions of the same law, U.S. Code text repeated across titles). On the built file: no document
  shares a 50-token shingle with a training or validation row (bench_guard, 22,461 rows); against the
  quick, full and `long` documents the shared share is at most 4.1% per document (boilerplate) except
  the synthetic `hardneg` documents (53% to 64%: they draw sentences from the same project-written
  bank by design). The sanitizer rejects or shortens no `long5` document (dry pass, no model).

Dropped for R5: Vietnamese legal datasets on Hugging Face (`minhnguyent546/vietnamese-legal-documents`
and its source `th1nhng0/…`, `YuITC/Vietnamese-Legal-Documents`): their text was taken from
thuvienphapluat.vn or has no stated origin, the portal R2b dropped because its terms were not verified (`corpus.yaml`, `dropped`).

## Attacks

`bench/long/embed_long.py --eval-payloads 40 --eval-skip 32`: 40 payloads per language (rows 33 to 72 of
build.py's seeded order of the eval/ dev-half attack rows of 40 to 600 characters; none of them is an R3
payload), bench split by the payload id (build.py `split_of`): 47 dev payloads (26 EN, 21 VI, 376
documents) and 33 holdout (14 EN, 19 VI, 264 documents); no payload shares a 50-token shingle with a
training row, each scored alone (`control`) and embedded in a `long5` benign document
of its own language and split in the seven variants of R3 (`pos_start`, `pos_end`, `pos_random`,
`straddle_window`, `straddle_chunk`, `straddle_segment`, `split_adjacent`), host drawn with the seeded
generator of R3 (seed 20261111). No host had to be left out (the sanitizer dry pass above). An attack document whose payload is not
found whole in the sanitized text is excluded and counted (as in R3). Detection of a document: the
decision blocks it; reported next to it: the payload's own windows blocking.

## Candidates

θ = 0.85, α = 0.01. Every candidate is a pair (rule set, decision).

**Rule sets.** `v6`: the L1 rules as shipped. `r5`: the rules of this commit, which change only:

1. Vietnamese homographs (`rules/homograph.go`): "giàu" (rich) is set apart from "giấu" (hide), "nhưng"
   (but) from "nhúng" (embed) and "những"; lowercase unmarked "hay" (or) and "ai" (who) are set apart
   from "hãy" and "AI" when at least two of the two words before and after carry Vietnamese marks (a
   message without marks keeps them). (Seen in R3: "giàu" in tp.secrecy/ii.hidden_note four times,
   "hay là … tự do", "Không ai được xâm phạm … tự do", "giấu kín … nhưng".)
2. `tp.secrecy`: the single adverbs (silently, secretly, quietly, covertly, âm thầm, lặng lẽ, giấu) move
   to `tp.secrecy.word` at 0.45, under the corroboration bar; `ii.hidden_note.word`: with them, an
   action of the note's kind (send verbs, reveal, reply, follow, change, replace, …; not "làm", "nói",
   "in") in the same sentence within eight words (the phrases keep the old cross-sentence rule).
3. `jb.refusal_suppression`: "without" counts only with the plural, a disclaimer or a gerund
   (`jb.refusal_suppression.without`); "without warning and" no longer matches.
4. `pe.password_tricks`: an encoding (base64, hex, encode) counts only with a request to disclose
   (`pe.password_encoded*`); the other tricks are unchanged.
5. `obf.decode_follow`: "ngược lại" (on the contrary) alone is no longer a decode cue ("đọc ngược lại"
   is).

`de.send_sensitive` is unchanged: a draft that lowered it to 0.45 lost data-exfiltration rows of the L1
baseline test (`internal/evalset`, eval/data with L1 alone), as did a draft with a four-word gap for
`ii.hidden_note.word` and a whole-text test for "hay"/"ai"; they were changed to the above before this
commit (disclosed: that test reads all eval/data rows, dev and holdout, with L1 only). With the rules
above that test passes, and on eval/data the L1 score of every attack row stays at 0.88 or more where
it was before (twelve attack rows change rules, no benign row; the largest drop is 0.891 to 0.884).

Unit tests (`rules/homograph_test.go`) keep the attacks of each rule matching and the prose examples
under the bar; every existing rule test passes.

**Decisions** (applied to texts of more than n0 windows; shorter texts as today, any window ≥ θ):

| decision | a window blocks when |
|---|---|
| `base` | s ≥ θ (today) |
| `corr` | s ≥ θ and L1 corroborates: calibrated L1 ≥ cal(0.5) (0.588) or a floor applied (R3's `corr`) |
| `agree` | as `corr`, but a floor counts only when L2 agrees: calibrated L2 ≥ 0.5; a floor without L2's agreement does not corroborate, and the window's score becomes min(s, the fused score without the floor) |
| `strong65` | as `agree` with the bar cal(0.65) (0.726) |
| `strong75` | as `agree` with the bar cal(0.75) (0.771) |

cal(x) is the L1 calibration (`fusion.DefaultL1Calibration`, A 0.998, B 0.356) of a raw rule weight; the
fused score without the floor is the `l1,l2` combiner of the v6 calibration on (L1, min(L2, 0.88)).
Candidates, in this order (the last tie-break, fewer changes first): `v6:corr`, `v6:agree`,
`v6:strong65`, `v6:strong75`, `r5:base`, `r5:corr`, `r5:agree`, `r5:strong65`, `r5:strong75`;
reference `v6:base`.

**n0**: from the dev `v6` benign windows as in R3: p̂ = share of windows ≥ θ, n0 = floor(ln(1 − α) /
ln(1 − p̂)).

## Rule-set gate (r5 candidates only)

`cmd/eval -detector fusion-ml` with the v6 classifier on the direct path, once with each rule set:
eval/data dev slice TPR at FPR ≤ 1%, and val_v3 (the v4-A build's selection split, as gate G5 of v6) TPR
at 0.85. The `r5` rule set passes when neither value is below the lower end of the two-sided 95%
Clopper–Pearson interval of the `v6` value (k = round(TPR × attacks)). An `r5` candidate that fails the
gate is not eligible. The FPR of both sets is reported, not gated (every R5 change only narrows a match).

## Selection rule (dev only)

Per candidate on the dev slice: **FPR criterion**: blocked dev benign 100k + 200k documents (EN and VI
pooled) ≤ α × documents; **TPR criterion**: detection of the embedded dev documents (seven variants
pooled, EN and VI pooled) ≥ detection of the dev payloads alone − 0.05, both under the candidate (the
payloads alone under the candidate's rule set).

1. Among eligible candidates meeting both: the highest embedded detection; tie: fewer blocked dev benign
   documents; tie: the order above.
2. If none meets both: among eligible candidates meeting the TPR criterion, the fewest blocked dev benign
   documents (tie: higher embedded detection, then the order). Reported as not meeting the target.
3. If none meets the TPR criterion: no change; the gateway keeps today's decision.

## Holdout (once)

After this file and the dev result are committed: the holdout benign documents and the holdout attack
documents are scored once with the chosen candidate's rule set, and once with the `v6` rule set as the
reference (v6 as it is; one run when the chosen candidate uses the `v6` rules); `longdoc_r5.py holdout` applies the chosen decision with its dev n0. Reported
whatever the result, with two-sided Clopper–Pearson 95% intervals: blocked benign documents per
language and size and pooled; detection alone, per variant and embedded, per language and pooled. No
parameter, candidate or criterion changes after that.

## Implementation commitment

- A decision other than `base` is written into the v6 package's `calibration.json` (`long_doc`, extended
  for `agree`/`strongX`) only if the chosen candidate meets both criteria on dev. Otherwise the decision
  is recorded and not shipped (as R3).
- The `r5` rule set stays in the code if it passes its gate and, on dev, `r5:base` blocks no more benign
  documents than `v6:base` and meets the TPR criterion; otherwise it is reverted before the PR merges.
- The short path is unchanged except through the rule set.
