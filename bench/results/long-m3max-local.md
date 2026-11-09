## Long inputs: m3max-local

- Model: `guardspec-classifier-v3b` (SHA-256 `87368d45526a`), ONNX Runtime 1.31.1
- CPU: Apple M3 Max, 14 vCPU (darwin/arm64); INFERENCE_MAX_CONCURRENCY=14, INFERENCE_INTRA_OP_THREADS=""
- Commit: `e32570d7eaa4`; date 2026-11-09T11:48:06Z
- Corpus: profile `quick`, 346 documents, docs.jsonl SHA-256 `b38614e21008f052`
- Layers: l2, l1/max, l1,l2/logreg; block threshold 0.85

### Score pass

346 documents, 1588150 tokens, 8435 L2 windows and 3935 fused chunks in 211 s with 4 documents at a time (7510 tokens/s, 2566 CPU-s).

### Latency and CPU (one document at a time)

`l2` scores the whole text as batched 256-token windows; the fused rows score the gateway's 2048-byte chunks, K at a time. intra 0 is ONNX Runtime's default.

| Path | intra | K | ms/window | windows/s | tokens/s | CPU-s per 1k tokens | max tokens in 10 s |
|---|---:|---:|---:|---:|---:|---:|---:|
| l2 | 1 | 1 | 61.6 | 16.2 | 3094 | 0.323 | 30939 |
| l1,l2/logreg | 1 | 1 | 61.8 | 16.2 | 2388 | 0.419 | 23875 |
| l1,l2/logreg | 1 | 2 | 31.6 | 31.7 | 4675 | 0.426 | 46748 |
| l1,l2/logreg | 1 | 4 | 16.0 | 62.4 | 9209 | 0.426 | 92085 |
| l2 | 0 | 1 | 10.8 | 92.7 | 17653 | 0.388 | 176532 |
| l1,l2/logreg | 0 | 1 | 12.0 | 83.3 | 12292 | 0.569 | 122920 |
| l1,l2/logreg | 0 | 2 | 9.6 | 104.6 | 15434 | 0.518 | 154338 |
| l1,l2/logreg | 0 | 4 | 8.4 | 118.9 | 17551 | 0.565 | 175507 |

Wall time per document (ms):

| Path | intra | K | wiki-en-20000-0 (20k tok) | wiki-vi-20000-0 (20k tok) |
|---|---:|---:|---:|---:|
| l2 | 1 | 1 | 6460 | 6467 |
| l1,l2/logreg | 1 | 1 | 8972 | 7780 |
| l1,l2/logreg | 1 | 2 | 4584 | 3972 |
| l1,l2/logreg | 1 | 4 | 2325 | 2018 |
| l2 | 0 | 1 | 1140 | 1126 |
| l1,l2/logreg | 0 | 1 | 1739 | 1515 |
| l1,l2/logreg | 0 | 2 | 1366 | 1226 |
| l1,l2/logreg | 0 | 4 | 1223 | 1056 |

### Benign score distribution per unit

| Layer | Lang | Genre | units | p50 | p90 | p99 | p99.9 | max | >= block |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| l2 | en | chat | 105 | 0.004 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | en | code | 368 | 0.229 | 0.958 | 0.980 | 0.984 | 0.987 | 23.6% |
| l2 | en | csv | 105 | 0.004 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | en | email | 105 | 0.004 | 0.004 | 0.004 | 0.005 | 0.005 | 0.0% |
| l2 | en | hardneg | 105 | 0.021 | 0.154 | 0.548 | 0.647 | 0.658 | 0.0% |
| l2 | en | json | 105 | 0.005 | 0.005 | 0.006 | 0.008 | 0.009 | 0.0% |
| l2 | en | legal | 368 | 0.030 | 0.386 | 0.874 | 0.939 | 0.941 | 1.9% |
| l2 | en | logs | 105 | 0.006 | 0.015 | 0.066 | 0.444 | 0.488 | 0.0% |
| l2 | en | wiki | 894 | 0.016 | 0.212 | 0.749 | 0.894 | 0.920 | 0.2% |
| l2 | vi | chat | 105 | 0.004 | 0.004 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | vi | csv | 105 | 0.004 | 0.004 | 0.004 | 0.005 | 0.005 | 0.0% |
| l2 | vi | email | 105 | 0.004 | 0.004 | 0.004 | 0.004 | 0.004 | 0.0% |
| l2 | vi | hardneg | 105 | 0.006 | 0.024 | 0.460 | 0.673 | 0.696 | 0.0% |
| l2 | vi | json | 105 | 0.005 | 0.006 | 0.047 | 0.051 | 0.052 | 0.0% |
| l2 | vi | legal | 367 | 0.005 | 0.006 | 0.019 | 0.198 | 0.222 | 0.0% |
| l2 | vi | literature | 368 | 0.005 | 0.007 | 0.028 | 0.115 | 0.143 | 0.0% |
| l2 | vi | logs | 105 | 0.076 | 0.958 | 0.978 | 0.979 | 0.979 | 21.9% |
| l2 | vi | wiki | 894 | 0.005 | 0.021 | 0.453 | 0.824 | 0.853 | 0.1% |
| l1/max | en | chat | 46 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | code | 128 | 0.227 | 0.435 | 0.814 | 0.941 | 0.960 | 0.8% |
| l1/max | en | csv | 35 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | email | 46 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | hardneg | 53 | 0.890 | 0.971 | 0.971 | 0.971 | 0.971 | 60.4% |
| l1/max | en | json | 26 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | legal | 174 | 0.227 | 0.227 | 0.759 | 0.849 | 0.849 | 0.0% |
| l1/max | en | logs | 30 | 0.189 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | wiki | 424 | 0.227 | 0.227 | 0.726 | 0.929 | 0.935 | 0.5% |
| l1/max | vi | chat | 52 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | csv | 39 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | email | 52 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | hardneg | 61 | 0.893 | 0.961 | 0.984 | 0.987 | 0.987 | 50.8% |
| l1/max | vi | json | 27 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | legal | 229 | 0.227 | 0.227 | 0.743 | 0.880 | 0.921 | 0.4% |
| l1/max | vi | literature | 170 | 0.227 | 0.664 | 0.921 | 0.921 | 0.921 | 10.0% |
| l1/max | vi | logs | 33 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | wiki | 489 | 0.227 | 0.227 | 0.921 | 0.931 | 0.935 | 2.0% |
| l1,l2/logreg | en | chat | 46 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l1,l2/logreg | en | code | 128 | 0.868 | 0.961 | 0.980 | 0.982 | 0.982 | 51.6% |
| l1,l2/logreg | en | csv | 35 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l1,l2/logreg | en | email | 46 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l1,l2/logreg | en | hardneg | 53 | 0.184 | 0.682 | 0.907 | 0.922 | 0.924 | 5.7% |
| l1,l2/logreg | en | json | 26 | 0.005 | 0.006 | 0.008 | 0.008 | 0.008 | 0.0% |
| l1,l2/logreg | en | legal | 174 | 0.096 | 0.579 | 0.871 | 0.947 | 0.960 | 1.7% |
| l1,l2/logreg | en | logs | 30 | 0.010 | 0.113 | 0.628 | 0.770 | 0.786 | 0.0% |
| l1,l2/logreg | en | wiki | 424 | 0.029 | 0.351 | 0.801 | 0.932 | 0.938 | 0.7% |
| l1,l2/logreg | vi | chat | 52 | 0.005 | 0.006 | 0.060 | 0.066 | 0.067 | 0.0% |
| l1,l2/logreg | vi | csv | 39 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l1,l2/logreg | vi | email | 52 | 0.005 | 0.005 | 0.011 | 0.012 | 0.012 | 0.0% |
| l1,l2/logreg | vi | hardneg | 61 | 0.038 | 0.268 | 0.754 | 0.875 | 0.888 | 1.6% |
| l1,l2/logreg | vi | json | 27 | 0.006 | 0.029 | 0.470 | 0.605 | 0.620 | 0.0% |
| l1,l2/logreg | vi | legal | 229 | 0.005 | 0.012 | 0.066 | 0.432 | 0.517 | 0.0% |
| l1,l2/logreg | vi | literature | 170 | 0.010 | 0.211 | 0.928 | 0.963 | 0.966 | 2.4% |
| l1,l2/logreg | vi | logs | 33 | 0.920 | 0.966 | 0.969 | 0.970 | 0.970 | 78.8% |
| l1,l2/logreg | vi | wiki | 489 | 0.007 | 0.050 | 0.561 | 0.910 | 0.924 | 0.4% |

### Benign documents flagged at the block threshold, by size

| Layer | Lang | Size | docs | mean units | FPR | gateway FPR |
|---|---|---|---:|---:|---:|---:|
| l2 | en | 20k | 9 | 105 | 22.2% | 22.2% |
| l2 | en | 50k | 3 | 263 | 100.0% | 100.0% |
| l2 | en | 100k | 1 | 526 | 100.0% | 100.0% |
| l2 | vi | 20k | 9 | 105 | 11.1% | 11.1% |
| l2 | vi | 50k | 3 | 263 | 0.0% | 0.0% |
| l2 | vi | 100k | 1 | 526 | 100.0% | 100.0% |
| l1/max | en | 20k | 9 | 41 | 11.1% | 11.1% |
| l1/max | en | 50k | 3 | 114 | 66.7% | 66.7% |
| l1/max | en | 100k | 1 | 252 | 100.0% | 100.0% |
| l1/max | vi | 20k | 9 | 48 | 22.2% | 22.2% |
| l1/max | vi | 50k | 3 | 142 | 100.0% | 100.0% |
| l1/max | vi | 100k | 1 | 293 | 100.0% | 100.0% |
| l1,l2/logreg | en | 20k | 9 | 41 | 44.4% | 44.4% |
| l1,l2/logreg | en | 50k | 3 | 114 | 66.7% | 66.7% |
| l1,l2/logreg | en | 100k | 1 | 252 | 100.0% | 100.0% |
| l1,l2/logreg | vi | 20k | 9 | 48 | 33.3% | 33.3% |
| l1,l2/logreg | vi | 50k | 3 | 142 | 66.7% | 66.7% |
| l1,l2/logreg | vi | 100k | 1 | 293 | 100.0% | 100.0% |

### T(n): threshold for 1% false positives over n units

FPR@block is the share of n-unit benign stretches whose maximum reaches 0.85. T is the larger of the bootstrap and GEV estimates.

| Layer | Lang | units | n | FPR@block | bootstrap q99 | GEV q99 | Gumbel q99 | T(n) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| l2 | en | 2260 | 1 | 4.2% | 0.968 | 0.896 | 0.880 | 0.968 |
| l2 | en | 2260 | 16 | 20.4% | 0.981 | 0.997 | 1.000 | 0.997 |
| l2 | en | 2260 | 64 | 34.8% | 0.987 | 0.999 | 1.000 | 0.999 |
| l2 | en | 2260 | 256 | 64.8% | 0.987 | 1.000 | 1.000 | 1.000 |
| l2 | en | 2260 | 1024 * | 100.0% | 0.987 | 1.000 | 1.000 | 1.000 |
| l2 | en | 2260 | 2630 * | 100.0% | 0.987 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 2259 | 1 | 1.1% | 0.853 | 0.106 | 0.185 | 0.853 |
| l2 | vi (provisional) | 2259 | 16 | 5.9% | 0.978 | 1.000 | 0.959 | 1.000 |
| l2 | vi (provisional) | 2259 | 64 | 10.2% | 0.979 | 1.000 | 0.996 | 1.000 |
| l2 | vi (provisional) | 2259 | 256 | 27.2% | 0.979 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 2259 | 1024 * | 91.5% | 0.979 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 2259 | 2630 * | 100.0% | 0.979 | 1.000 | 1.000 | 1.000 |
| l1/max | en | 962 | 1 | 3.6% | 0.971 | 0.640 | 0.756 | 0.971 |
| l1/max | en | 962 | 16 | 12.1% | 0.971 | 1.000 | 0.984 | 1.000 |
| l1/max | en | 962 | 64 | 32.0% | 0.971 | 1.000 | 0.996 | 1.000 |
| l1/max | en | 962 | 256 * | 91.9% | 0.971 | 1.000 | 0.999 | 1.000 |
| l1/max | en | 962 | 1024 * | 100.0% | 0.971 | 1.000 | 1.000 | 1.000 |
| l1/max | en | 962 | 2630 * | 100.0% | 0.971 | 1.000 | 1.000 | 1.000 |
| l1/max | vi (provisional) | 1152 | 1 | 5.1% | 0.952 | 0.863 | 0.877 | 0.952 |
| l1/max | vi (provisional) | 1152 | 16 | 31.9% | 0.987 | 0.999 | 0.997 | 0.999 |
| l1/max | vi (provisional) | 1152 | 64 | 67.1% | 0.987 | 1.000 | 0.999 | 1.000 |
| l1/max | vi (provisional) | 1152 | 256 * | 100.0% | 0.987 | 1.000 | 1.000 | 1.000 |
| l1/max | vi (provisional) | 1152 | 1024 * | 100.0% | 0.987 | 1.000 | 1.000 | 1.000 |
| l1/max | vi (provisional) | 1152 | 2630 * | 100.0% | 0.987 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | en | 962 | 1 | 7.8% | 0.961 | 0.948 | 0.946 | 0.961 |
| l1,l2/logreg | en | 962 | 16 | 26.1% | 0.982 | 0.985 | 1.000 | 0.985 |
| l1,l2/logreg | en | 962 | 64 | 49.8% | 0.982 | 0.987 | 1.000 | 0.987 |
| l1,l2/logreg | en | 962 | 256 * | 96.2% | 0.982 | 0.988 | 1.000 | 0.988 |
| l1,l2/logreg | en | 962 | 1024 * | 100.0% | 0.982 | 0.988 | 1.000 | 0.988 |
| l1,l2/logreg | en | 962 | 2630 * | 100.0% | 0.982 | 0.988 | 1.000 | 0.988 |
| l1,l2/logreg | vi (provisional) | 1152 | 1 | 2.9% | 0.942 | 0.686 | 0.680 | 0.942 |
| l1,l2/logreg | vi (provisional) | 1152 | 16 | 13.9% | 0.970 | 0.998 | 0.999 | 0.998 |
| l1,l2/logreg | vi (provisional) | 1152 | 64 | 38.4% | 0.970 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | vi (provisional) | 1152 | 256 * | 96.3% | 0.970 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | vi (provisional) | 1152 | 1024 * | 100.0% | 0.970 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | vi (provisional) | 1152 | 2630 * | 100.0% | 0.970 | 1.000 | 1.000 | 1.000 |

\* n is more than a fifth of the benign stream: a weak bootstrap estimate.

### Attacks in long text: detection rate

At the block threshold, at T(n) for the document's own number of units, and as the gateway decides (score or sanitizer anomaly). `control` is the payload alone.

| Layer | Lang | Variant | docs | mean units | TPR@block | TPR@T(n) | gateway | hosts flagged |
|---|---|---|---:|---:|---:|---:|---:|---:|
| l2 | en | control | 12 | 1 | 100.0% | 91.7% | 100.0% | 0 |
| l2 | en | pos_start | 12 | 11 | 33.3% | 0.0% | 33.3% | 0 |
| l2 | en | pos_end | 12 | 11 | 25.0% | 0.0% | 25.0% | 0 |
| l2 | en | pos_random | 12 | 11 | 8.3% | 0.0% | 8.3% | 0 |
| l2 | en | straddle_window | 12 | 11 | 25.0% | 0.0% | 25.0% | 0 |
| l2 | en | straddle_chunk | 12 | 11 | 0.0% | 0.0% | 0.0% | 0 |
| l2 | en | straddle_segment | 12 | 38 | 0.0% | 0.0% | 0.0% | 0 |
| l2 | en | split_adjacent | 12 | 11 | 16.7% | 0.0% | 16.7% | 0 |
| l2 | en | split_far | 12 | 11 | 8.3% | 0.0% | 8.3% | 0 |
| l2 | en | hidden_zero_width | 12 | 11 | 25.0% | 0.0% | 25.0% | 0 |
| l2 | en | hidden_tags | 12 | 11 | 0.0% | 0.0% | 100.0% | 0 |
| l2 | en | genre_code_comment | 12 | 11 | 83.3% | 0.0% | 83.3% | 0 |
| l2 | en | genre_json_field | 12 | 11 | 91.7% | 0.0% | 91.7% | 0 |
| l2 | vi | control | 12 | 1 | 91.7% | 91.7% | 91.7% | 0 |
| l2 | vi | pos_start | 12 | 11 | 16.7% | 0.0% | 16.7% | 0 |
| l2 | vi | pos_end | 12 | 11 | 25.0% | 0.0% | 25.0% | 0 |
| l2 | vi | pos_random | 12 | 11 | 8.3% | 0.0% | 8.3% | 0 |
| l2 | vi | straddle_window | 12 | 11 | 25.0% | 0.0% | 25.0% | 0 |
| l2 | vi | straddle_chunk | 12 | 11 | 8.3% | 0.0% | 8.3% | 0 |
| l2 | vi | straddle_segment | 12 | 32 | 8.3% | 0.0% | 8.3% | 0 |
| l2 | vi | split_adjacent | 12 | 11 | 0.0% | 0.0% | 0.0% | 0 |
| l2 | vi | split_far | 12 | 11 | 8.3% | 0.0% | 8.3% | 0 |
| l2 | vi | hidden_zero_width | 12 | 11 | 16.7% | 0.0% | 16.7% | 0 |
| l2 | vi | hidden_tags | 12 | 11 | 0.0% | 0.0% | 100.0% | 0 |
| l2 | vi | genre_code_comment | 12 | 11 | 50.0% | 0.0% | 50.0% | 0 |
| l2 | vi | genre_json_field | 12 | 11 | 66.7% | 0.0% | 66.7% | 0 |
| l1/max | en | control | 12 | 1 | 91.7% | 33.3% | 91.7% | 0 |
| l1/max | en | pos_start | 12 | 5 | 75.0% | 33.3% | 75.0% | 0 |
| l1/max | en | pos_end | 12 | 5 | 91.7% | 33.3% | 91.7% | 0 |
| l1/max | en | pos_random | 12 | 5 | 83.3% | 41.7% | 83.3% | 0 |
| l1/max | en | straddle_window | 12 | 5 | 91.7% | 33.3% | 91.7% | 0 |
| l1/max | en | straddle_chunk | 12 | 5 | 66.7% | 33.3% | 66.7% | 0 |
| l1/max | en | straddle_segment | 12 | 17 | 91.7% | 0.0% | 91.7% | 0 |
| l1/max | en | split_adjacent | 12 | 5 | 66.7% | 25.0% | 66.7% | 0 |
| l1/max | en | split_far | 12 | 5 | 66.7% | 8.3% | 66.7% | 0 |
| l1/max | en | hidden_zero_width | 12 | 5 | 83.3% | 33.3% | 83.3% | 0 |
| l1/max | en | hidden_tags | 12 | 5 | 0.0% | 0.0% | 100.0% | 0 |
| l1/max | en | genre_code_comment | 12 | 3 | 83.3% | 66.7% | 83.3% | 0 |
| l1/max | en | genre_json_field | 12 | 3 | 91.7% | 75.0% | 91.7% | 0 |
| l1/max | vi | control | 12 | 1 | 91.7% | 83.3% | 91.7% | 0 |
| l1/max | vi | pos_start | 12 | 6 | 91.7% | 33.3% | 91.7% | 0 |
| l1/max | vi | pos_end | 12 | 6 | 91.7% | 33.3% | 91.7% | 0 |
| l1/max | vi | pos_random | 12 | 6 | 91.7% | 33.3% | 91.7% | 0 |
| l1/max | vi | straddle_window | 12 | 6 | 83.3% | 33.3% | 83.3% | 0 |
| l1/max | vi | straddle_chunk | 12 | 6 | 91.7% | 33.3% | 91.7% | 0 |
| l1/max | vi | straddle_segment | 12 | 17 | 100.0% | 0.0% | 100.0% | 12 |
| l1/max | vi | split_adjacent | 12 | 6 | 83.3% | 8.3% | 83.3% | 0 |
| l1/max | vi | split_far | 12 | 6 | 83.3% | 8.3% | 83.3% | 0 |
| l1/max | vi | hidden_zero_width | 12 | 6 | 91.7% | 33.3% | 91.7% | 0 |
| l1/max | vi | hidden_tags | 12 | 6 | 0.0% | 0.0% | 100.0% | 0 |
| l1/max | vi | genre_code_comment | 12 | 3 | 75.0% | 58.3% | 75.0% | 0 |
| l1/max | vi | genre_json_field | 12 | 3 | 83.3% | 75.0% | 83.3% | 0 |
| l1,l2/logreg | en | control | 12 | 1 | 100.0% | 100.0% | 100.0% | 0 |
| l1,l2/logreg | en | pos_start | 12 | 5 | 50.0% | 33.3% | 50.0% | 0 |
| l1,l2/logreg | en | pos_end | 12 | 5 | 41.7% | 41.7% | 41.7% | 0 |
| l1,l2/logreg | en | pos_random | 12 | 5 | 33.3% | 25.0% | 33.3% | 0 |
| l1,l2/logreg | en | straddle_window | 12 | 5 | 100.0% | 91.7% | 100.0% | 0 |
| l1,l2/logreg | en | straddle_chunk | 12 | 5 | 58.3% | 41.7% | 58.3% | 0 |
| l1,l2/logreg | en | straddle_segment | 12 | 17 | 50.0% | 41.7% | 50.0% | 0 |
| l1,l2/logreg | en | split_adjacent | 12 | 5 | 33.3% | 25.0% | 33.3% | 0 |
| l1,l2/logreg | en | split_far | 12 | 5 | 8.3% | 0.0% | 8.3% | 0 |
| l1,l2/logreg | en | hidden_zero_width | 12 | 5 | 41.7% | 25.0% | 41.7% | 0 |
| l1,l2/logreg | en | hidden_tags | 12 | 5 | 0.0% | 0.0% | 100.0% | 0 |
| l1,l2/logreg | en | genre_code_comment | 12 | 3 | 91.7% | 83.3% | 91.7% | 0 |
| l1,l2/logreg | en | genre_json_field | 12 | 3 | 91.7% | 75.0% | 91.7% | 0 |
| l1,l2/logreg | vi | control | 12 | 1 | 91.7% | 91.7% | 91.7% | 0 |
| l1,l2/logreg | vi | pos_start | 12 | 6 | 50.0% | 41.7% | 50.0% | 0 |
| l1,l2/logreg | vi | pos_end | 12 | 6 | 58.3% | 41.7% | 58.3% | 0 |
| l1,l2/logreg | vi | pos_random | 12 | 6 | 33.3% | 33.3% | 33.3% | 0 |
| l1,l2/logreg | vi | straddle_window | 12 | 6 | 50.0% | 25.0% | 50.0% | 0 |
| l1,l2/logreg | vi | straddle_chunk | 12 | 6 | 41.7% | 25.0% | 41.7% | 0 |
| l1,l2/logreg | vi | straddle_segment | 12 | 17 | 66.7% | 0.0% | 66.7% | 0 |
| l1,l2/logreg | vi | split_adjacent | 12 | 6 | 16.7% | 16.7% | 16.7% | 0 |
| l1,l2/logreg | vi | split_far | 12 | 6 | 25.0% | 8.3% | 25.0% | 0 |
| l1,l2/logreg | vi | hidden_zero_width | 12 | 6 | 58.3% | 25.0% | 58.3% | 0 |
| l1,l2/logreg | vi | hidden_tags | 12 | 6 | 0.0% | 0.0% | 100.0% | 0 |
| l1,l2/logreg | vi | genre_code_comment | 12 | 3 | 66.7% | 66.7% | 66.7% | 0 |
| l1,l2/logreg | vi | genre_json_field | 12 | 3 | 91.7% | 91.7% | 91.7% | 0 |

### Notes

- Scores are calibrated probabilities: l2 is the classifier's Platt-calibrated risk per 256-token window (64-token overlap); the fused rows are the gateway's injection score per 2048-byte chunk (24 KiB segments, no 16-chunk cap).
- The block threshold is the gateway's 0.85. T(n) is the threshold that keeps a benign text of n units (windows or chunks) under 1% false positives: the larger of a block-bootstrap q99 of the maximum over n contiguous units and a GEV extrapolation fitted to 16-unit block maxima on the logit scale.
- Vietnamese thresholds are provisional: the Vietnamese benign corpus is smaller and less varied than the English one.
- Attack payloads are attack rows of the eval/ hold-out half; TPR counts a document as detected when its maximum reaches the threshold. Hidden-character payloads are stripped by the sanitizer, which raises the anomaly score instead (the 'gateway' column also counts anomaly >= 0.6).
- split_far places the two halves of a payload about 1,500 tokens apart, so no window sees both: a known limitation of window scoring.
