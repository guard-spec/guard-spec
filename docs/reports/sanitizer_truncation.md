# Sanitizer: what it cut, what it rejected, and the fix (RF-4131836b)

Copyright The Guard Spec Authors. Licensed under the Apache License 2.0.

## The problem

Before this change the gateway forwarded the sanitizer's HTML-stripped text (bluemonday). Two things went wrong:

- **Cut text.** Anything that looked like a tag was removed before the model upstream saw it: JSX and HTML in
  code, placeholders such as `<key>`, and, because an HTML parser treats the content of `script`, `style`,
  `textarea` and `plaintext` as raw text or drops it, everything after a mere mention of those tags.
- **Rejected text.** Each cleaning pass removed one mention of `<textarea>` or `<plaintext>`, so a document with
  nine or more mentions never became stable and was rejected as "input exceeds 8 layers of encoding".
- The same cut also hid what follows a `<script>` mention from the detectors, which is a way to slip an
  instruction past them.

## The change

`sanitizer.Clean` returns two views and the report:

- **Forward** (what the gateway sends upstream): the input as written, minus invisible and bidi characters, ANSI
  escapes, control characters and spoofed markers. NFKC is applied first only when a marker was found.
- **Scan** (what the detectors read): the old pipeline with bluemonday replaced by `stripTags`. Each tag becomes
  the text of its attribute values (layout, address and identifier attributes are skipped). The content of every
  element is kept. Hidden HTML is marked as before. CRLF and CR become LF.

`/guardrail/sanitize` returns the scan view.

## Measurements

All numbers from `cmd/sanitizecheck` (new in this change). "Truncated" means more than 1% of a text's bytes
removed in the scan view; "rejected" means the sanitizer returned an error. After the change the forwarded view
removes only invisible characters, so nothing is cut from what the user's model receives.

| Corpus | texts | removed bytes before → after | truncated before → after | rejected before → after |
|---|---:|---:|---:|---:|
| bench quick | 346 | 20,985 → 20,633 | 49 → 48 | 0 → 0 |
| bench full | 912 | 809,477 → 55,296 | 133 → 129 | 0 → 0 |
| bench long | 128 | 2,511,948 → 842,400 | 22 → 11 | **2 → 0** |
| bench long5 | 150 | 1,437,644 → 103,155 | 19 → 6 | 0 → 0 |
| eval/data en | 926 | 3,995 → 3,995 | 54 → 54 | 0 → 0 |
| eval/data vi | 1,250 | 3,701 → 3,527 | 55 → 49 | 0 → 0 |
| eval/codelog | 310 | 36,350 → 11,697 | 49 → 40 | 0 → 0 |
| eval/embedded | 2,176 | 163,930 → 58,715 | 540 → 466 | 0 → 0 |

What the scan view still removes is tag markup itself, CRLF → LF and invisible characters.

### Detection: `cmd/eval`, v3b, fusion-ml, ONNX INT8 on CPU

| Set | before | after |
|---|---|---|
| eval/data | — | identical decisions |
| eval/codelog (benign, path tool) | 24 / 310 blocked | 25 / 310 blocked |
| eval/embedded attacks | 889 / 1,171 caught | 904 / 1,171 caught |
| eval/embedded benign | 43 blocked | 43 blocked |

The CI gate `embedded no-corroboration` fell on vi/obfuscation tpr@0.60 from 0.824 to 0.794: one row of 34, a JSX
diff whose payload is tag characters (the gateway's anomaly score blocks it anyway). Overall on that baseline AUC
went 0.910 → 0.922 and TPR at 0.85 0.793 → 0.809 (FPR 0.128 → 0.130); that baseline was refreshed.

### Long documents: v8e on `long5` (`cmd/benchlong -long on -layers none -l2pass off`)

Same model, calibration and corpora as `train/reports/v8e_parity.md` (dev set since R5; no holdout opened). Built
from `efce436`, ONNX INT8 on the laptop's CPU, 2026-11-15.

| | before (`fac5610`) | after (`efce436`) |
|---|---:|---:|
| Benign documents blocked | 0 / 150 | 0 / 150 |
| Embedded attacks caught at the block threshold | 481 / 560 | 487 / 560 |
| Embedded attacks blocked by the gateway (score or anomaly) | 488 / 560 | 494 / 560 |
| Payloads alone | 69 / 80 | 69 / 80 |
| L2 windows (attack set) | 431,774 | 439,076 |
| Wall time, attack set (4 workers) | 6,000 s | 5,129 s |

The scan view keeps about 1–2% more text per document, hence more windows. Counted by variant, English
`straddle_segment` loses one document (36 → 35 of 40) and five other variants gain seven between them.

## Security checks

- `go test ./...` passes.
- `FuzzSanitize` (scan view: no marker, no ignorable or control character, idempotent) and `FuzzClean` (forward
  view: no marker, no ignorable or control character; Scan equals `Sanitize`) ran 10 minutes each with no failure.
- New unit tests: an instruction after `<script>`, `<style>`, `<textarea>`, `<plaintext>`, `<xmp>`, `<noscript>`,
  `<title>` (also entity-encoded) reaches the scan view; 40 mentions of `<textarea>` are neither rejected nor cut.

### What stays open

- The forwarded view keeps HTML entities as written. An entity-encoded legacy `[DATA]` marker is caught in the
  scan view (and raises the marker signal) but stays encoded in the forwarded text; spotlighting boundaries are
  random per request, so they cannot be pre-encoded.
- Attribute values on the skip list (`href`, `src`, `class`, `style`, …) are not scanned.

## Reproduce

```sh
go build -o sc ./cmd/sanitizecheck
./sc -json out.json eval/data/en.jsonl eval/data/vi.jsonl eval/codelog/codelog.jsonl eval/embedded/embedded.jsonl
# long path: see train/reports/v8e_parity.md, with the binary built from this commit
```
