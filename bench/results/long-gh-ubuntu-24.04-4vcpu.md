## Long inputs: gh-ubuntu-24.04-4vcpu

- Model: `guardspec-classifier-v3b` (SHA-256 `87368d45526a`), ONNX Runtime 1.31.1
- CPU: AMD EPYC 7763 64-Core Processor, 4 vCPU (linux/amd64); INFERENCE_MAX_CONCURRENCY=4, INFERENCE_INTRA_OP_THREADS=""
- Commit: `be8f04fd57eb`; date 2026-11-09T12:53:22Z
- Corpus: profile `full`, 912 documents, docs.jsonl SHA-256 `a5dcef89f18809a1`
- Layers: l2, l1/max, l1,l2/logreg; block threshold 0.85

### Score pass

912 documents, 9379585 tokens, 49604 L2 windows and 21642 fused chunks in 6909 s with 4 documents at a time (1358 tokens/s, 27551 CPU-s).

### Latency and CPU (one document at a time)

`l2` scores the whole text as batched 256-token windows; the fused rows score the gateway's 2048-byte chunks, K at a time. intra 0 is ONNX Runtime's default.

| Path | intra | K | ms/window | windows/s | tokens/s | CPU-s per 1k tokens | max tokens in 10 s |
|---|---:|---:|---:|---:|---:|---:|---:|
| l2 | 1 | 1 | 103.0 | 9.7 | 1850 | 0.541 | 18499 |
| l1,l2/logreg | 1 | 1 | 101.0 | 9.9 | 1462 | 0.686 | 14615 |
| l1,l2/logreg | 1 | 2 | 51.8 | 19.3 | 2850 | 0.700 | 28496 |
| l1,l2/logreg | 1 | 4 | 47.5 | 21.0 | 3106 | 1.267 | 31060 |
| l2 | 0 | 1 | 51.4 | 19.5 | 3707 | 1.072 | 37073 |
| l1,l2/logreg | 0 | 1 | 52.2 | 19.2 | 2829 | 1.408 | 28286 |
| l1,l2/logreg | 0 | 2 | 57.1 | 17.5 | 2583 | 1.545 | 25829 |
| l1,l2/logreg | 0 | 4 | 53.0 | 18.9 | 2784 | 1.433 | 27842 |

Wall time per document (ms):

| Path | intra | K | wiki-en-20000-0 (20k tok) | wiki-vi-20000-0 (20k tok) |
|---|---:|---:|---:|---:|
| l2 | 1 | 1 | 10823 | 10799 |
| l1,l2/logreg | 1 | 1 | 14676 | 12691 |
| l1,l2/logreg | 1 | 2 | 7555 | 6481 |
| l1,l2/logreg | 1 | 4 | 6912 | 5966 |
| l2 | 0 | 1 | 5395 | 5394 |
| l1,l2/logreg | 0 | 1 | 7617 | 6524 |
| l1,l2/logreg | 0 | 2 | 8246 | 7240 |
| l1,l2/logreg | 0 | 4 | 7588 | 6778 |

### Benign score distribution per unit

| Layer | Lang | Genre | units | p50 | p90 | p99 | p99.9 | max | >= block |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| l2 | en | chat | 1940 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | en | code | 1925 | 0.049 | 0.897 | 0.976 | 0.985 | 0.990 | 13.0% |
| l2 | en | csv | 1947 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | en | email | 1935 | 0.005 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | en | hardneg | 1920 | 0.014 | 0.096 | 0.409 | 0.828 | 0.847 | 0.0% |
| l2 | en | json | 1947 | 0.005 | 0.005 | 0.007 | 0.014 | 0.016 | 0.0% |
| l2 | en | legal | 4556 | 0.014 | 0.183 | 0.763 | 0.935 | 0.974 | 0.6% |
| l2 | en | logs | 1947 | 0.006 | 0.015 | 0.150 | 0.869 | 0.939 | 0.2% |
| l2 | en | wiki | 4579 | 0.009 | 0.096 | 0.728 | 0.943 | 0.978 | 0.4% |
| l2 | vi | chat | 1941 | 0.004 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | vi | csv | 1945 | 0.004 | 0.005 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | vi | email | 1937 | 0.004 | 0.004 | 0.005 | 0.005 | 0.005 | 0.0% |
| l2 | vi | hardneg | 1924 | 0.006 | 0.034 | 0.572 | 0.895 | 0.904 | 0.2% |
| l2 | vi | json | 1947 | 0.005 | 0.008 | 0.619 | 0.953 | 0.956 | 0.5% |
| l2 | vi | legal | 892 | 0.005 | 0.006 | 0.016 | 0.276 | 0.297 | 0.0% |
| l2 | vi | literature | 368 | 0.005 | 0.008 | 0.044 | 0.106 | 0.117 | 0.0% |
| l2 | vi | logs | 1947 | 0.067 | 0.955 | 0.977 | 0.982 | 0.983 | 22.5% |
| l2 | vi | wiki | 3802 | 0.006 | 0.056 | 0.742 | 0.949 | 0.952 | 0.5% |
| l1/max | en | chat | 838 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | code | 612 | 0.227 | 0.227 | 0.880 | 0.943 | 0.960 | 2.1% |
| l1/max | en | csv | 644 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | email | 843 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | hardneg | 979 | 0.922 | 0.971 | 0.971 | 0.984 | 0.984 | 68.1% |
| l1/max | en | json | 482 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | legal | 2055 | 0.227 | 0.227 | 0.726 | 0.937 | 0.959 | 0.2% |
| l1/max | en | logs | 557 | 0.189 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | en | wiki | 2162 | 0.227 | 0.227 | 0.726 | 0.914 | 0.935 | 0.2% |
| l1/max | vi | chat | 961 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | csv | 722 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | email | 969 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | hardneg | 1116 | 0.927 | 0.961 | 0.984 | 0.992 | 0.993 | 59.8% |
| l1/max | vi | json | 511 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | legal | 549 | 0.227 | 0.435 | 0.759 | 0.931 | 0.942 | 0.7% |
| l1/max | vi | literature | 170 | 0.227 | 0.664 | 0.921 | 0.921 | 0.921 | 10.0% |
| l1/max | vi | logs | 607 | 0.227 | 0.227 | 0.227 | 0.227 | 0.227 | 0.0% |
| l1/max | vi | wiki | 2102 | 0.227 | 0.227 | 0.921 | 0.967 | 0.988 | 2.0% |
| l1,l2/logreg | en | chat | 838 | 0.005 | 0.005 | 0.005 | 0.006 | 0.006 | 0.0% |
| l1,l2/logreg | en | code | 612 | 0.529 | 0.947 | 0.972 | 0.980 | 0.984 | 27.9% |
| l1,l2/logreg | en | csv | 644 | 0.005 | 0.005 | 0.006 | 0.006 | 0.006 | 0.0% |
| l1,l2/logreg | en | email | 843 | 0.005 | 0.005 | 0.005 | 0.005 | 0.006 | 0.0% |
| l1,l2/logreg | en | hardneg | 979 | 0.151 | 0.668 | 0.962 | 0.987 | 0.997 | 4.2% |
| l1,l2/logreg | en | json | 482 | 0.006 | 0.007 | 0.009 | 0.014 | 0.015 | 0.0% |
| l1,l2/logreg | en | legal | 2055 | 0.040 | 0.460 | 0.919 | 0.972 | 0.988 | 2.0% |
| l1,l2/logreg | en | logs | 557 | 0.010 | 0.055 | 0.524 | 0.784 | 0.803 | 0.0% |
| l1,l2/logreg | en | wiki | 2162 | 0.015 | 0.194 | 0.820 | 0.944 | 0.968 | 0.7% |
| l1,l2/logreg | vi | chat | 961 | 0.005 | 0.007 | 0.769 | 0.966 | 0.968 | 0.8% |
| l1,l2/logreg | vi | csv | 722 | 0.005 | 0.005 | 0.005 | 0.010 | 0.020 | 0.0% |
| l1,l2/logreg | vi | email | 969 | 0.005 | 0.005 | 0.021 | 0.666 | 0.963 | 0.1% |
| l1,l2/logreg | vi | hardneg | 1116 | 0.049 | 0.245 | 0.806 | 0.943 | 0.945 | 0.9% |
| l1,l2/logreg | vi | json | 511 | 0.007 | 0.341 | 0.905 | 0.947 | 0.957 | 3.1% |
| l1,l2/logreg | vi | legal | 549 | 0.006 | 0.010 | 0.059 | 0.246 | 0.411 | 0.0% |
| l1,l2/logreg | vi | literature | 170 | 0.011 | 0.166 | 0.947 | 0.971 | 0.974 | 2.4% |
| l1,l2/logreg | vi | logs | 607 | 0.906 | 0.962 | 0.970 | 0.974 | 0.974 | 64.7% |
| l1,l2/logreg | vi | wiki | 2102 | 0.008 | 0.133 | 0.826 | 0.940 | 0.988 | 0.9% |

### Benign documents flagged at the block threshold, by size

| Layer | Lang | Size | docs | mean units | FPR | gateway FPR |
|---|---|---|---:|---:|---:|---:|
| l2 | en | 20k | 9 | 105 | 22.2% | 22.2% |
| l2 | en | 50k | 9 | 263 | 44.4% | 44.4% |
| l2 | en | 100k | 9 | 523 | 44.4% | 44.4% |
| l2 | en | 200k | 9 | 1048 | 44.4% | 44.4% |
| l2 | en | 500k | 2 | 2624 | 100.0% | 100.0% |
| l2 | vi | 20k | 9 | 105 | 11.1% | 11.1% |
| l2 | vi | 50k | 9 | 263 | 33.3% | 33.3% |
| l2 | vi | 100k | 8 | 525 | 37.5% | 37.5% |
| l2 | vi | >100k | 1 | 1855 | 100.0% | 100.0% |
| l2 | vi | 200k | 7 | 1049 | 57.1% | 57.1% |
| l1/max | en | 20k | 9 | 41 | 11.1% | 11.1% |
| l1/max | en | 50k | 9 | 103 | 33.3% | 33.3% |
| l1/max | en | 100k | 9 | 206 | 44.4% | 44.4% |
| l1/max | en | 200k | 9 | 404 | 44.4% | 44.4% |
| l1/max | en | 500k | 2 | 1190 | 100.0% | 100.0% |
| l1/max | vi | 20k | 9 | 48 | 22.2% | 22.2% |
| l1/max | vi | 50k | 9 | 121 | 44.4% | 44.4% |
| l1/max | vi | 100k | 8 | 242 | 37.5% | 37.5% |
| l1/max | vi | >100k | 1 | 1028 | 100.0% | 100.0% |
| l1/max | vi | 200k | 7 | 461 | 28.6% | 28.6% |
| l1,l2/logreg | en | 20k | 9 | 41 | 44.4% | 44.4% |
| l1,l2/logreg | en | 50k | 9 | 103 | 44.4% | 44.4% |
| l1,l2/logreg | en | 100k | 9 | 206 | 44.4% | 44.4% |
| l1,l2/logreg | en | 200k | 9 | 404 | 44.4% | 44.4% |
| l1,l2/logreg | en | 500k | 2 | 1190 | 100.0% | 100.0% |
| l1,l2/logreg | vi | 20k | 9 | 48 | 33.3% | 33.3% |
| l1,l2/logreg | vi | 50k | 9 | 121 | 33.3% | 33.3% |
| l1,l2/logreg | vi | 100k | 8 | 242 | 62.5% | 62.5% |
| l1,l2/logreg | vi | >100k | 1 | 1028 | 100.0% | 100.0% |
| l1,l2/logreg | vi | 200k | 7 | 461 | 85.7% | 85.7% |

### T(n): threshold for 1% false positives over n units

FPR@block is the share of n-unit benign stretches whose maximum reaches 0.85. T is the larger of the bootstrap and GEV estimates.

| Layer | Lang | units | n | FPR@block | bootstrap q99 | GEV q99 | Gumbel q99 | T(n) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| l2 | en | 22696 | 1 | 1.3% | 0.884 | 0.460 | 0.485 | 0.884 |
| l2 | en | 22696 | 16 | 8.6% | 0.977 | 0.999 | 0.997 | 0.999 |
| l2 | en | 22696 | 64 | 16.9% | 0.984 | 1.000 | 1.000 | 1.000 |
| l2 | en | 22696 | 256 | 33.5% | 0.990 | 1.000 | 1.000 | 1.000 |
| l2 | en | 22696 | 1024 | 53.8% | 0.990 | 1.000 | 1.000 | 1.000 |
| l2 | en | 22696 | 2630 | 64.6% | 0.990 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 16703 | 1 | 2.8% | 0.958 | 0.379 | 0.506 | 0.958 |
| l2 | vi (provisional) | 16703 | 16 | 14.0% | 0.979 | 1.000 | 0.998 | 1.000 |
| l2 | vi (provisional) | 16703 | 64 | 21.1% | 0.982 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 16703 | 256 | 37.3% | 0.983 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 16703 | 1024 | 55.4% | 0.983 | 1.000 | 1.000 | 1.000 |
| l2 | vi (provisional) | 16703 | 2630 | 78.8% | 0.983 | 1.000 | 1.000 | 1.000 |
| l1/max | en | 9172 | 1 | 7.5% | 0.971 | 0.541 | 0.710 | 0.971 |
| l1/max | en | 9172 | 16 | 13.0% | 0.971 | 1.000 | 0.975 | 1.000 |
| l1/max | en | 9172 | 64 | 18.7% | 0.984 | 1.000 | 0.994 | 1.000 |
| l1/max | en | 9172 | 256 | 37.4% | 0.984 | 1.000 | 0.998 | 1.000 |
| l1/max | en | 9172 | 1024 | 64.1% | 0.984 | 1.000 | 1.000 | 1.000 |
| l1/max | en | 9172 | 2630 * | 91.2% | 0.984 | 1.000 | 1.000 | 1.000 |
| l1/max | vi (provisional) | 7707 | 1 | 9.5% | 0.976 | 0.756 | 0.849 | 0.976 |
| l1/max | vi (provisional) | 7707 | 16 | 23.4% | 0.988 | 1.000 | 0.996 | 1.000 |
| l1/max | vi (provisional) | 7707 | 64 | 36.4% | 0.993 | 1.000 | 0.999 | 1.000 |
| l1/max | vi (provisional) | 7707 | 256 | 51.0% | 0.993 | 1.000 | 1.000 | 1.000 |
| l1/max | vi (provisional) | 7707 | 1024 | 61.3% | 0.993 | 1.000 | 1.000 | 1.000 |
| l1/max | vi (provisional) | 7707 | 2630 * | 82.2% | 0.993 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | en | 9172 | 1 | 2.9% | 0.949 | 0.861 | 0.843 | 0.949 |
| l1,l2/logreg | en | 9172 | 16 | 18.3% | 0.984 | 0.998 | 1.000 | 0.998 |
| l1,l2/logreg | en | 9172 | 64 | 36.3% | 0.988 | 0.999 | 1.000 | 0.999 |
| l1,l2/logreg | en | 9172 | 256 | 60.3% | 0.997 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | en | 9172 | 1024 | 73.8% | 0.997 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | en | 9172 | 2630 * | 91.3% | 0.997 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | vi (provisional) | 7707 | 1 | 5.9% | 0.960 | 0.827 | 0.811 | 0.960 |
| l1,l2/logreg | vi (provisional) | 7707 | 16 | 18.4% | 0.972 | 0.999 | 1.000 | 0.999 |
| l1,l2/logreg | vi (provisional) | 7707 | 64 | 40.1% | 0.974 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | vi (provisional) | 7707 | 256 | 68.7% | 0.988 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | vi (provisional) | 7707 | 1024 | 97.9% | 0.988 | 1.000 | 1.000 | 1.000 |
| l1,l2/logreg | vi (provisional) | 7707 | 2630 * | 100.0% | 0.988 | 1.000 | 1.000 | 1.000 |

\* n is more than a fifth of the benign stream: a weak bootstrap estimate.

### Attacks in long text: detection rate

At the block threshold, at T(n) for the document's own number of units, and as the gateway decides (score or sanitizer anomaly). `control` is the payload alone.

| Layer | Lang | Variant | docs | mean units | TPR@block | TPR@T(n) | gateway | hosts flagged |
|---|---|---|---:|---:|---:|---:|---:|---:|
| l2 | en | control | 32 | 1 | 93.8% | 93.8% | 96.9% | 0 |
| l2 | en | pos_start | 32 | 11 | 15.6% | 0.0% | 18.8% | 0 |
| l2 | en | pos_end | 32 | 11 | 25.0% | 0.0% | 28.1% | 0 |
| l2 | en | pos_random | 32 | 11 | 12.5% | 0.0% | 15.6% | 0 |
| l2 | en | straddle_window | 32 | 11 | 15.6% | 0.0% | 18.8% | 0 |
| l2 | en | straddle_chunk | 32 | 11 | 0.0% | 0.0% | 3.1% | 0 |
| l2 | en | straddle_segment | 32 | 38 | 0.0% | 0.0% | 3.1% | 0 |
| l2 | en | split_adjacent | 32 | 11 | 9.4% | 0.0% | 12.5% | 0 |
| l2 | en | split_far | 32 | 11 | 3.1% | 0.0% | 6.2% | 0 |
| l2 | en | hidden_zero_width | 32 | 11 | 21.9% | 0.0% | 25.0% | 0 |
| l2 | en | hidden_tags | 32 | 11 | 0.0% | 0.0% | 100.0% | 0 |
| l2 | en | genre_code_comment | 32 | 11 | 71.9% | 0.0% | 75.0% | 0 |
| l2 | en | genre_json_field | 32 | 11 | 84.4% | 0.0% | 87.5% | 0 |
| l2 | vi | control | 32 | 1 | 93.8% | 87.5% | 93.8% | 0 |
| l2 | vi | pos_start | 32 | 11 | 15.6% | 0.0% | 15.6% | 0 |
| l2 | vi | pos_end | 32 | 11 | 28.1% | 0.0% | 28.1% | 0 |
| l2 | vi | pos_random | 32 | 11 | 6.2% | 0.0% | 6.2% | 0 |
| l2 | vi | straddle_window | 32 | 11 | 21.9% | 0.0% | 21.9% | 0 |
| l2 | vi | straddle_chunk | 32 | 11 | 6.2% | 0.0% | 6.2% | 0 |
| l2 | vi | straddle_segment | 32 | 32 | 3.1% | 0.0% | 3.1% | 0 |
| l2 | vi | split_adjacent | 32 | 11 | 3.1% | 0.0% | 3.1% | 0 |
| l2 | vi | split_far | 32 | 11 | 6.2% | 0.0% | 6.2% | 0 |
| l2 | vi | hidden_zero_width | 32 | 11 | 15.6% | 0.0% | 15.6% | 0 |
| l2 | vi | hidden_tags | 32 | 11 | 0.0% | 0.0% | 100.0% | 0 |
| l2 | vi | genre_code_comment | 32 | 11 | 56.2% | 0.0% | 56.2% | 0 |
| l2 | vi | genre_json_field | 32 | 11 | 65.6% | 0.0% | 65.6% | 0 |
| l1/max | en | control | 32 | 1 | 84.4% | 56.2% | 87.5% | 0 |
| l1/max | en | pos_start | 32 | 5 | 71.9% | 50.0% | 75.0% | 0 |
| l1/max | en | pos_end | 32 | 5 | 84.4% | 56.2% | 87.5% | 0 |
| l1/max | en | pos_random | 32 | 5 | 78.1% | 56.2% | 81.2% | 0 |
| l1/max | en | straddle_window | 32 | 5 | 84.4% | 56.2% | 87.5% | 0 |
| l1/max | en | straddle_chunk | 32 | 5 | 65.6% | 46.9% | 68.8% | 0 |
| l1/max | en | straddle_segment | 32 | 17 | 84.4% | 0.0% | 87.5% | 0 |
| l1/max | en | split_adjacent | 32 | 5 | 65.6% | 40.6% | 68.8% | 0 |
| l1/max | en | split_far | 32 | 5 | 68.8% | 31.2% | 71.9% | 0 |
| l1/max | en | hidden_zero_width | 32 | 5 | 78.1% | 50.0% | 81.2% | 0 |
| l1/max | en | hidden_tags | 32 | 5 | 0.0% | 0.0% | 100.0% | 0 |
| l1/max | en | genre_code_comment | 32 | 3 | 78.1% | 68.8% | 81.2% | 0 |
| l1/max | en | genre_json_field | 32 | 3 | 84.4% | 78.1% | 87.5% | 0 |
| l1/max | vi | control | 32 | 1 | 87.5% | 34.4% | 87.5% | 0 |
| l1/max | vi | pos_start | 32 | 6 | 87.5% | 0.0% | 87.5% | 0 |
| l1/max | vi | pos_end | 32 | 6 | 87.5% | 0.0% | 87.5% | 0 |
| l1/max | vi | pos_random | 32 | 6 | 87.5% | 0.0% | 87.5% | 0 |
| l1/max | vi | straddle_window | 32 | 6 | 81.2% | 0.0% | 81.2% | 0 |
| l1/max | vi | straddle_chunk | 32 | 6 | 87.5% | 0.0% | 87.5% | 0 |
| l1/max | vi | straddle_segment | 32 | 17 | 100.0% | 0.0% | 100.0% | 32 |
| l1/max | vi | split_adjacent | 32 | 6 | 84.4% | 0.0% | 84.4% | 0 |
| l1/max | vi | split_far | 32 | 6 | 84.4% | 0.0% | 84.4% | 0 |
| l1/max | vi | hidden_zero_width | 32 | 6 | 87.5% | 0.0% | 87.5% | 0 |
| l1/max | vi | hidden_tags | 32 | 6 | 0.0% | 0.0% | 100.0% | 0 |
| l1/max | vi | genre_code_comment | 32 | 3 | 75.0% | 37.5% | 75.0% | 0 |
| l1/max | vi | genre_json_field | 32 | 3 | 78.1% | 46.9% | 78.1% | 0 |
| l1,l2/logreg | en | control | 32 | 1 | 93.8% | 93.8% | 96.9% | 0 |
| l1,l2/logreg | en | pos_start | 32 | 5 | 62.5% | 37.5% | 65.6% | 0 |
| l1,l2/logreg | en | pos_end | 32 | 5 | 56.2% | 56.2% | 59.4% | 0 |
| l1,l2/logreg | en | pos_random | 32 | 5 | 50.0% | 40.6% | 53.1% | 0 |
| l1,l2/logreg | en | straddle_window | 32 | 5 | 84.4% | 71.9% | 87.5% | 0 |
| l1,l2/logreg | en | straddle_chunk | 32 | 5 | 59.4% | 40.6% | 62.5% | 0 |
| l1,l2/logreg | en | straddle_segment | 32 | 17 | 59.4% | 9.4% | 62.5% | 0 |
| l1,l2/logreg | en | split_adjacent | 32 | 5 | 43.8% | 25.0% | 46.9% | 0 |
| l1,l2/logreg | en | split_far | 32 | 5 | 15.6% | 9.4% | 18.8% | 0 |
| l1,l2/logreg | en | hidden_zero_width | 32 | 5 | 50.0% | 37.5% | 53.1% | 0 |
| l1,l2/logreg | en | hidden_tags | 32 | 5 | 0.0% | 0.0% | 100.0% | 0 |
| l1,l2/logreg | en | genre_code_comment | 32 | 3 | 87.5% | 71.9% | 90.6% | 0 |
| l1,l2/logreg | en | genre_json_field | 32 | 3 | 84.4% | 81.2% | 87.5% | 0 |
| l1,l2/logreg | vi | control | 32 | 1 | 93.8% | 90.6% | 93.8% | 0 |
| l1,l2/logreg | vi | pos_start | 32 | 6 | 25.0% | 6.2% | 25.0% | 0 |
| l1,l2/logreg | vi | pos_end | 32 | 6 | 31.2% | 6.2% | 31.2% | 0 |
| l1,l2/logreg | vi | pos_random | 32 | 6 | 25.0% | 3.1% | 25.0% | 0 |
| l1,l2/logreg | vi | straddle_window | 32 | 6 | 31.2% | 3.1% | 31.2% | 0 |
| l1,l2/logreg | vi | straddle_chunk | 32 | 6 | 31.2% | 0.0% | 31.2% | 0 |
| l1,l2/logreg | vi | straddle_segment | 32 | 17 | 50.0% | 0.0% | 50.0% | 0 |
| l1,l2/logreg | vi | split_adjacent | 32 | 6 | 12.5% | 0.0% | 12.5% | 0 |
| l1,l2/logreg | vi | split_far | 32 | 6 | 12.5% | 0.0% | 12.5% | 0 |
| l1,l2/logreg | vi | hidden_zero_width | 32 | 6 | 25.0% | 0.0% | 25.0% | 0 |
| l1,l2/logreg | vi | hidden_tags | 32 | 6 | 0.0% | 0.0% | 100.0% | 0 |
| l1,l2/logreg | vi | genre_code_comment | 32 | 3 | 71.9% | 56.2% | 71.9% | 0 |
| l1,l2/logreg | vi | genre_json_field | 32 | 3 | 84.4% | 75.0% | 84.4% | 0 |

### Notes

- Scores are calibrated probabilities: l2 is the classifier's Platt-calibrated risk per 256-token window (64-token overlap); the fused rows are the gateway's injection score per 2048-byte chunk (24 KiB segments, no 16-chunk cap).
- The block threshold is the gateway's 0.85. T(n) is the threshold that keeps a benign text of n units (windows or chunks) under 1% false positives: the larger of a block-bootstrap q99 of the maximum over n contiguous units and a GEV extrapolation fitted to 16-unit block maxima on the logit scale.
- Vietnamese thresholds are provisional: the Vietnamese benign corpus is smaller and less varied than the English one.
- Attack payloads are attack rows of the eval/ hold-out half; TPR counts a document as detected when its maximum reaches the threshold. Hidden-character payloads are stripped by the sanitizer, which raises the anomaly score instead (the 'gateway' column also counts anomaly >= 0.6).
- split_far places the two halves of a payload about 1,500 tokens apart, so no window sees both: a known limitation of window scoring.
