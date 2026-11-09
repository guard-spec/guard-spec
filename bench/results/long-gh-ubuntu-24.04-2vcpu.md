## Long inputs: gh-ubuntu-24.04-2vcpu

- Model: `guardspec-classifier-v3b` (SHA-256 `87368d45526a`), ONNX Runtime 1.31.1
- CPU: AMD EPYC 9V74 80-Core Processor, 2 vCPU (linux/amd64); INFERENCE_MAX_CONCURRENCY=2, INFERENCE_INTRA_OP_THREADS=""
- Commit: `be8f04fd57eb`; date 2026-11-09T12:52:38Z
- Corpus: profile `quick`, 346 documents, docs.jsonl SHA-256 `b38614e21008f052`
- Layers: l2, l1/max, l1,l2/logreg; block threshold 0.85

### Score pass

346 documents, 1588150 tokens, 8435 L2 windows and 3935 fused chunks in 1142 s with 2 documents at a time (1390 tokens/s, 2285 CPU-s).

### Latency and CPU (one document at a time)

`l2` scores the whole text as batched 256-token windows; the fused rows score the gateway's 2048-byte chunks, K at a time. intra 0 is ONNX Runtime's default.

| Path | intra | K | ms/window | windows/s | tokens/s | CPU-s per 1k tokens | max tokens in 10 s |
|---|---:|---:|---:|---:|---:|---:|---:|
| l2 | 1 | 1 | 64.8 | 15.4 | 2939 | 0.341 | 29390 |
| l1,l2/logreg | 1 | 1 | 60.3 | 16.6 | 2449 | 0.410 | 24489 |
| l1,l2/logreg | 1 | 2 | 51.3 | 19.5 | 2879 | 0.692 | 28791 |
| l2 | 0 | 1 | 30.4 | 32.9 | 6263 | 0.634 | 62630 |
| l1,l2/logreg | 0 | 1 | 29.2 | 34.3 | 5060 | 0.788 | 50599 |
| l1,l2/logreg | 0 | 2 | 32.3 | 31.0 | 4571 | 0.872 | 45712 |

Wall time per document (ms):

| Path | intra | K | wiki-en-20000-0 (20k tok) | wiki-vi-20000-0 (20k tok) |
|---|---:|---:|---:|---:|
| l2 | 1 | 1 | 6816 | 6793 |
| l1,l2/logreg | 1 | 1 | 8718 | 7615 |
| l1,l2/logreg | 1 | 2 | 7457 | 6435 |
| l2 | 0 | 1 | 3197 | 3189 |
| l1,l2/logreg | 0 | 1 | 4231 | 3674 |
| l1,l2/logreg | 0 | 2 | 4687 | 4063 |

### Benign score distribution per unit

| Layer | Lang | Genre | units | p50 | p90 | p99 | p99.9 | max | >= block |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| l2 | en | chat | 105 | 0.004 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | en | code | 368 | 0.261 | 0.960 | 0.980 | 0.986 | 0.989 | 23.4% |
| l2 | en | csv | 105 | 0.004 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | en | email | 105 | 0.004 | 0.004 | 0.004 | 0.005 | 0.005 | 0.0% |
| l2 | en | hardneg | 105 | 0.019 | 0.158 | 0.546 | 0.657 | 0.670 | 0.0% |
| l2 | en | json | 105 | 0.005 | 0.005 | 0.006 | 0.009 | 0.009 | 0.0% |
| l2 | en | legal | 368 | 0.031 | 0.362 | 0.872 | 0.929 | 0.931 | 1.6% |
| l2 | en | logs | 105 | 0.006 | 0.014 | 0.147 | 0.375 | 0.401 | 0.0% |
| l2 | en | wiki | 894 | 0.016 | 0.214 | 0.741 | 0.907 | 0.922 | 0.3% |
| l2 | vi | chat | 105 | 0.004 | 0.004 | 0.004 | 0.005 | 0.005 | 0.0% |
| l2 | vi | csv | 105 | 0.004 | 0.004 | 0.004 | 0.005 | 0.005 | 0.0% |
| l2 | vi | email | 105 | 0.004 | 0.004 | 0.004 | 0.004 | 0.004 | 0.0% |
| l2 | vi | hardneg | 105 | 0.006 | 0.028 | 0.561 | 0.644 | 0.651 | 0.0% |
| l2 | vi | json | 105 | 0.005 | 0.006 | 0.041 | 0.208 | 0.227 | 0.0% |
| l2 | vi | legal | 367 | 0.005 | 0.006 | 0.017 | 0.199 | 0.213 | 0.0% |
| l2 | vi | literature | 368 | 0.005 | 0.007 | 0.027 | 0.172 | 0.215 | 0.0% |
| l2 | vi | logs | 105 | 0.045 | 0.947 | 0.981 | 0.982 | 0.982 | 21.9% |
| l2 | vi | wiki | 894 | 0.005 | 0.021 | 0.477 | 0.793 | 0.869 | 0.1% |
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
| l1,l2/logreg | en | code | 128 | 0.863 | 0.961 | 0.978 | 0.983 | 0.984 | 51.6% |
| l1,l2/logreg | en | csv | 35 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l1,l2/logreg | en | email | 46 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l1,l2/logreg | en | hardneg | 53 | 0.183 | 0.681 | 0.912 | 0.918 | 0.919 | 3.8% |
| l1,l2/logreg | en | json | 26 | 0.005 | 0.006 | 0.007 | 0.007 | 0.007 | 0.0% |
| l1,l2/logreg | en | legal | 174 | 0.092 | 0.582 | 0.884 | 0.952 | 0.955 | 1.7% |
| l1,l2/logreg | en | logs | 30 | 0.009 | 0.159 | 0.661 | 0.784 | 0.797 | 0.0% |
| l1,l2/logreg | en | wiki | 424 | 0.027 | 0.355 | 0.849 | 0.934 | 0.937 | 1.2% |
| l1,l2/logreg | vi | chat | 52 | 0.005 | 0.007 | 0.120 | 0.203 | 0.212 | 0.0% |
| l1,l2/logreg | vi | csv | 39 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l1,l2/logreg | vi | email | 52 | 0.005 | 0.005 | 0.012 | 0.015 | 0.016 | 0.0% |
| l1,l2/logreg | vi | hardneg | 61 | 0.039 | 0.249 | 0.789 | 0.870 | 0.879 | 1.6% |
| l1,l2/logreg | vi | json | 27 | 0.006 | 0.072 | 0.389 | 0.426 | 0.430 | 0.0% |
| l1,l2/logreg | vi | legal | 229 | 0.005 | 0.012 | 0.054 | 0.404 | 0.479 | 0.0% |
| l1,l2/logreg | vi | literature | 170 | 0.011 | 0.217 | 0.917 | 0.952 | 0.959 | 2.4% |
| l1,l2/logreg | vi | logs | 33 | 0.925 | 0.966 | 0.970 | 0.970 | 0.970 | 81.8% |
| l1,l2/logreg | vi | wiki | 489 | 0.007 | 0.051 | 0.536 | 0.874 | 0.902 | 0.2% |

### Benign documents flagged at the block threshold, by size

| Layer | Lang | Size | docs | mean units | FPR | gateway FPR |
|---|---|---|---:|---:|---:|---:|
| l2 | en | 20k | 9 | 105 | 22.2% | 22.2% |
| l2 | en | 50k | 3 | 263 | 100.0% | 100.0% |
| l2 | en | 100k | 1 | 526 | 100.0% | 100.0% |
| l2 | vi | 20k | 9 | 105 | 11.1% | 11.1% |
| l2 | vi | 50k | 3 | 263 | 33.3% | 33.3% |
| l2 | vi | 100k | 1 | 526 | 0.0% | 0.0% |
| l1/max | en | 20k | 9 | 41 | 11.1% | 11.1% |
| l1/max | en | 50k | 3 | 114 | 66.7% | 66.7% |
| l1/max | en | 100k | 1 | 252 | 100.0% | 100.0% |
| l1/max | vi | 20k | 9 | 48 | 22.2% | 22.2% |
| l1/max | vi | 50k | 3 | 142 | 100.0% | 100.0% |
| l1/max | vi | 100k | 1 | 293 | 100.0% | 100.0% |
| l1,l2/logreg | en | 20k | 9 | 41 | 44.4% | 44.4% |
| l1,l2/logreg | en | 50k | 3 | 114 | 100.0% | 100.0% |
| l1,l2/logreg | en | 100k | 1 | 252 | 100.0% | 100.0% |
| l1,l2/logreg | vi | 20k | 9 | 48 | 33.3% | 33.3% |
| l1,l2/logreg | vi | 50k | 3 | 142 | 33.3% | 33.3% |
| l1,l2/logreg | vi | 100k | 1 | 293 | 100.0% | 100.0% |

### T(n): threshold for 1% false positives over n units

FPR@block is the share of n-unit benign stretches whose maximum reaches 0.85. T is the larger of the bootstrap and GEV estimates.

| Layer | Lang | units | n | FPR@block | bootstrap q99 | GEV q99 | Gumbel q99 | T(n) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| l2 | en | 2260 | 1 | 4.2% | 0.969 | 0.897 | 0.881 | 0.969 |
| l2 | en | 2260 | 16 | 20.7% | 0.981 | 0.997 | 1.000 | 0.997 |
| l2 | en | 2260 | 64 | 33.0% | 0.989 | 0.999 | 1.000 | 0.999 |
| l2 | en | 2260 | 256 | 63.1% | 0.989 | 1.000 | 1.000 | 1.000 |
| l2 | en | 2260 | 1024 * | 100.0% | 0.989 | 1.000 | 1.000 | 1.000 |
| l2 | en | 2260 | 2630 * | 100.0% | 0.989 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 2259 | 1 | 1.1% | 0.869 | 0.112 | 0.192 | 0.869 |
| l2 | vi (provisional) | 2259 | 16 | 5.6% | 0.981 | 1.000 | 0.963 | 1.000 |
| l2 | vi (provisional) | 2259 | 64 | 10.2% | 0.982 | 1.000 | 0.996 | 1.000 |
| l2 | vi (provisional) | 2259 | 256 | 27.2% | 0.982 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 2259 | 1024 * | 89.2% | 0.982 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 2259 | 2630 * | 100.0% | 0.982 | 1.000 | 1.000 | 1.000 |
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
| l1,l2/logreg | en | 962 | 1 | 7.9% | 0.962 | 0.949 | 0.947 | 0.962 |
| l1,l2/logreg | en | 962 | 16 | 28.4% | 0.984 | 0.984 | 1.000 | 0.984 |
| l1,l2/logreg | en | 962 | 64 | 60.4% | 0.984 | 0.986 | 1.000 | 0.986 |
| l1,l2/logreg | en | 962 | 256 * | 100.0% | 0.984 | 0.987 | 1.000 | 0.987 |
| l1,l2/logreg | en | 962 | 1024 * | 100.0% | 0.984 | 0.987 | 1.000 | 0.987 |
| l1,l2/logreg | en | 962 | 2630 * | 100.0% | 0.984 | 0.987 | 1.000 | 0.987 |
| l1,l2/logreg | vi (provisional) | 1152 | 1 | 2.9% | 0.943 | 0.701 | 0.687 | 0.943 |
| l1,l2/logreg | vi (provisional) | 1152 | 16 | 12.5% | 0.970 | 0.997 | 0.999 | 0.997 |
| l1,l2/logreg | vi (provisional) | 1152 | 64 | 32.8% | 0.970 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | vi (provisional) | 1152 | 256 * | 81.9% | 0.970 | 1.000 | 1.000 | 1.000 |
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
| l2 | en | genre_json_field | 12 | 11 | 91.7% | 8.3% | 91.7% | 0 |
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
| l1,l2/logreg | en | pos_start | 12 | 5 | 50.0% | 41.7% | 50.0% | 0 |
| l1,l2/logreg | en | pos_end | 12 | 5 | 41.7% | 41.7% | 41.7% | 0 |
| l1,l2/logreg | en | pos_random | 12 | 5 | 33.3% | 25.0% | 33.3% | 0 |
| l1,l2/logreg | en | straddle_window | 12 | 5 | 100.0% | 83.3% | 100.0% | 0 |
| l1,l2/logreg | en | straddle_chunk | 12 | 5 | 50.0% | 41.7% | 50.0% | 0 |
| l1,l2/logreg | en | straddle_segment | 12 | 17 | 50.0% | 41.7% | 50.0% | 0 |
| l1,l2/logreg | en | split_adjacent | 12 | 5 | 33.3% | 25.0% | 33.3% | 0 |
| l1,l2/logreg | en | split_far | 12 | 5 | 8.3% | 0.0% | 8.3% | 0 |
| l1,l2/logreg | en | hidden_zero_width | 12 | 5 | 41.7% | 25.0% | 41.7% | 0 |
| l1,l2/logreg | en | hidden_tags | 12 | 5 | 0.0% | 0.0% | 100.0% | 0 |
| l1,l2/logreg | en | genre_code_comment | 12 | 3 | 91.7% | 83.3% | 91.7% | 0 |
| l1,l2/logreg | en | genre_json_field | 12 | 3 | 91.7% | 83.3% | 91.7% | 0 |
| l1,l2/logreg | vi | control | 12 | 1 | 91.7% | 91.7% | 91.7% | 0 |
| l1,l2/logreg | vi | pos_start | 12 | 6 | 50.0% | 41.7% | 50.0% | 0 |
| l1,l2/logreg | vi | pos_end | 12 | 6 | 58.3% | 41.7% | 58.3% | 0 |
| l1,l2/logreg | vi | pos_random | 12 | 6 | 33.3% | 33.3% | 33.3% | 0 |
| l1,l2/logreg | vi | straddle_window | 12 | 6 | 50.0% | 25.0% | 50.0% | 0 |
| l1,l2/logreg | vi | straddle_chunk | 12 | 6 | 41.7% | 33.3% | 41.7% | 0 |
| l1,l2/logreg | vi | straddle_segment | 12 | 17 | 66.7% | 16.7% | 66.7% | 0 |
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
