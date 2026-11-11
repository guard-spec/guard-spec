<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Sizing

> Tiếng Việt: [sizing.vi.md](sizing.vi.md).

How much CPU, memory and disk Guard Spec needs, by detection layer. The
gateway dominates: its memory is set by which models it loads, and its CPU by
how many prompts per second the model layers score. The control plane and
Postgres are small next to it.

## Choosing layers

`DETECTOR_LAYERS` picks the layers (one variable, in `.env`):

| Mode | `DETECTOR_LAYERS` | Models pulled | Use it when |
|---|---|---|---|
| Full (default) | `l1,l2,l3` | classifier + e5 embedder, about 270 MB | Production with RAM to spare; L3 matches org-specific exemplars and adds recall on paraphrased attacks |
| Light | `l1,l2` | classifier only, about 135 MB | A laptop, a small VM, a personal setup; about half the memory and 2 to 3 times the throughput of full |
| Rules only | `l1` | none | Very small hosts, or when false positives cost more than missed attacks; much weaker on paraphrases |

```bash
# quick start in light mode (writes DETECTOR_LAYERS=l1,l2 into the new .env)
DETECTOR_LAYERS=l1,l2 scripts/quickstart.sh
# an existing stack: set DETECTOR_LAYERS=l1,l2 in .env, then
docker compose -f docker-compose.yml up -d
```

`models-init` pulls only what the layers need, and `/readyz` shows the active
layers (`"layers":["l1","l2"]`). What each layer detects and how they are
fused: README, [Models](../README.md#models) and
[Benchmarks](../README.md#benchmarks).

## Measured resource use

**Source.** Measured on 2026-11-06 by the maintainers on one machine: an
Apple M3 Max (arm64) MacBook Pro, Docker Desktop 28.4 with a Linux VM of
14 vCPUs and 15.4 GiB, images `ghcr.io/guard-spec/guard-spec-gateway:0.1.0`
(linux/arm64) and `-control-plane:0.1.0`, models `guardspec-classifier@v3b`
and `multilingual-e5-small@614241f`. Memory and CPU are `docker stats`
(sampled about once a second during the run; CPU 100% = one core). Load is
ApacheBench, 8 concurrent clients, `POST /v1/chat/completions` with a
system message and a 350-character user prompt, the stub upstream (no
`UPSTREAM_LLM_URL`), so the numbers are the guard's own cost; every request
also writes an audit row. Other hardware, x86-64 CPUs in particular, will
differ: measure on yours (below) before you size a fleet.

### Unconstrained (quick start, no limits)

The gateway may use all 14 vCPUs; `INFERENCE_MAX_CONCURRENCY` defaults to the
CPU count (14) and ORT uses 4 threads per run.

| Layers | Gateway RAM idle | Gateway RAM peak | Gateway CPU under load (mean / peak) | Requests/s | Latency p50 / p95 / p99 |
|---|---|---|---|---|---|
| L1 | 10 MiB | 28 MiB | 2.9 / 4.0 cores | 1,784 | 3 / 6 / 13 ms |
| L1 + L2 | 483 MiB | 511 MiB | 9.3 / 10.1 cores | 387 | 19 / 31 / 43 ms |
| L1 + L2 + L3 | 909 MiB | 942 MiB | 12.9 / 15.6 cores | 137 | 53 / 103 / 152 ms |

### With the production compose limits

[`deploy/compose/production`](../deploy/compose/production/README.md)
defaults: gateway limited to 2 CPUs and 2 GiB, `INFERENCE_MAX_CONCURRENCY=2`,
`INFERENCE_INTRA_OP_THREADS=1`; load sent from inside the compose network
straight to the gateway.

| Layers | Gateway RAM idle | Gateway RAM peak | Gateway CPU under load | Requests/s | Latency p50 / p95 / p99 |
|---|---|---|---|---|---|
| L1 | 11 MiB | 22 MiB | 1.5 cores | 2,168 | 2 / 9 / 23 ms |
| L1 + L2 | 481 MiB | 503 MiB | 1.9 cores | 118 | 68 / 74 / 79 ms |
| L1 + L2 + L3 | 904 MiB | 909 MiB | 1.9 cores | 55 | 138 / 166 / 288 ms |

With 8 clients and 2 model runs at a time, most of that latency is queueing:
one scan takes about 2 / throughput (17 ms light, 36 ms full on this CPU).

### The other services

| Service | RAM | CPU |
|---|---|---|
| Control plane | about 10 MiB, idle and under gateway load | under 1% |
| Postgres | 42 to 66 MiB idle, up to 100 MiB under the loads above | 0.3 cores at 137 audit writes/s, 0.6 at 387, 1.8 at 1,784 |
| Caddy (production compose) | up to 17 MiB | small |

## Recommendations

Starting points, from the tables above plus headroom. Only the "small team"
row matches a measured configuration; the others are extrapolated from it.
Requests/s are the guard alone; your upstream LLM's latency comes on top and
does not use the gateway's CPU while it waits.

| Setup | Layers | Host | Gateway limit | Roughly handles |
|---|---|---|---|---|
| Personal / laptop | `l1,l2` | 2 vCPU, 2 GB RAM free | none | tens of requests/s |
| Small team, one VM | `l1,l2` | 2 vCPU, 4 GB | 2 CPUs, 1 GiB | about 100 requests/s |
| Startup production, one VM | `l1,l2,l3` | 4 vCPU, 8 GB | 2 to 3 CPUs, 2 GiB | about 50 to 80 requests/s |
| More traffic | `l1,l2,l3` | several gateway replicas (Kubernetes, Helm chart) | 2 CPUs, 2 GiB each | add replicas; throughput scales with cores |

- Memory: give the gateway at least 1.5 x its measured peak (light 768 MiB,
  full 1.5 GiB); the model weights are loaded once per process, whatever the
  concurrency.
- CPU: throughput grows with cores up to `INFERENCE_MAX_CONCURRENCY` x
  `INFERENCE_INTRA_OP_THREADS`; set their product to the CPUs the gateway may
  use. More than that only adds contention.
- `DETECTOR_CASCADE=true` skips L2 and L3 when L1 alone is decisive, which
  saves CPU on obvious traffic; it changes scores, so check it against your
  traffic first.
- Rate limits (`RATE_LIMIT_RPM`) and an upstream timeout keep a burst from
  queueing up behind the model layers.
- Kubernetes: the Helm chart's gateway defaults (500m CPU / 1Gi request, 2Gi
  memory limit) fit the full detector's measured peak; set
  `INFERENCE_MAX_CONCURRENCY` and `INFERENCE_INTRA_OP_THREADS` to the CPU
  limit as above (`gateway.env`), and scale with `gateway.autoscaling` (HPA). See
  [`values.yaml`](../deploy/helm/guard-spec/values.yaml), the per-cloud
  examples in
  [`deploy/helm/guard-spec/examples/`](../deploy/helm/guard-spec/examples/)
  and [README, Kubernetes](../README.md#kubernetes).

## Long inputs

A long text costs CPU in proportion to its length: the gateway cuts it into
2,048-byte chunks (untrusted text first into 24 KiB segments) and the
classifier scores each chunk in 256-token windows. Today one request carries
at most 128 KiB of untrusted text (about 30k tokens) and a single message at
most 16 chunks; the numbers below say what larger documents would cost.
How well the detector does on long text (false positives grow with length)
is in [benchmark, Long documents](benchmark.md#long-documents).

Measured with `make bench-long` (`cmd/benchlong`, the `l1,l2` detector, one
document at a time, K chunks of a document scored in parallel; 20k-token
Wikipedia documents in English and Vietnamese). `intra` is
`INFERENCE_INTRA_OP_THREADS`; "ORT default" lets ONNX Runtime use every core
for each run.

| Hardware | Source | ms per window (intra 1) | Tokens/s, intra 1, K = 4 | Tokens/s, ORT default, K = 4 | Tokens scanned in 10 s (best) | CPU-s per 1k tokens | 20k-token document (best) |
|---|---|---:|---:|---:|---:|---:|---:|
| 2 vCPU (AMD EPYC 9V74) | GitHub ubuntu-24.04 runner, `taskset -c 0,1`, quick profile, 2026-11-09 | 60.3 | 2,879 (K = 2) | 4,571 (K = 2) | about 50,000 | 0.41 (intra 1), 0.79 (default) | 3.7 to 4.2 s |
| 4 vCPU (AMD EPYC 7763) | GitHub ubuntu-24.04 runner, full profile, 2026-11-09 | 101.0 | 3,106 | 2,784 | about 31,000 | 0.69 (intra 1), 1.41 (default) | 6.0 to 6.9 s |
| Apple M3 Max, 14 cores | M3 Max, local, indicative (2026-11-09, quick profile) | 61.8 | 9,209 | 17,551 | about 175,000 | 0.42 (intra 1), 0.57 (default) | 1.1 to 1.2 s |
| 8 vCPU (x86) | estimated | | about 6,000 | | about 60,000 | | about 3 s |
| 16 vCPU (x86) | estimated | | about 12,000 | | about 120,000 | | about 1.5 s |
| GPU | not measured (task RF-b74de2b9) | | | | | | |

- The two runner rows are measured, but on different CPUs (GitHub assigns
  the host): the 2 vCPU job got a newer EPYC 9V74, the 4 vCPU job an EPYC
  7763 that also ran the full corpus, so the 2 vCPU row is faster. Shared
  cloud vCPUs vary by 1.5 to 2 times between runs; read them as a range.
- x86 cloud vCPUs are 3 to 4 times slower per core than an M3 Max here
  (about 780 tokens/s per vCPU at intra 1, K = 4, on the 4 vCPU runner
  against about 2,300 per M3 Max core).
- The 8 and 16 vCPU rows are estimates, not measurements: they scale the
  4 vCPU runner's rate per vCPU linearly, which assumes K and
  `INFERENCE_MAX_CONCURRENCY` grow with the cores. Replace them with your
  own run.
- For a 10 s scanning budget this means roughly 30k to 50k tokens per
  request on 2 to 4 vCPU, 60k on 8 and 120k on 16 (estimated); 200k tokens
  in 10 s needs about 32 dedicated vCPUs or a GPU (not measured yet).
- CPU per token barely changes with K or intra: more parallelism cuts the
  wall time of one document, not its cost. A server scanning documents for
  several users at once gets the same total throughput from intra 1 and
  many concurrent runs as from fewer, wider runs.
- The full per-run tables (L2 alone, every K, wall time per document) are in
  [`bench/results/long-m3max-local.md`](../bench/results/long-m3max-local.md),
  [`long-gh-ubuntu-24.04-4vcpu.md`](../bench/results/long-gh-ubuntu-24.04-4vcpu.md)
  and [`long-gh-ubuntu-24.04-2vcpu.md`](../bench/results/long-gh-ubuntu-24.04-2vcpu.md).
  The runner runs predate the 0.4.2 code/log fixes, so their false-positive
  tables show the 0.4.1 detector; latency is unaffected.

### Measure long inputs on your hardware

```bash
make bench-long                    # PROFILE=quick: about 1.6M tokens, about 7 minutes on an M3 Max
make bench-long PROFILE=full       # about 9.5M tokens
# your own documents, no Python needed: one .txt file per document
go run -tags onnx ./cmd/benchlong -docs ./my-docs -lang en -host my-server
```

`make bench-long` needs [uv](https://docs.astral.sh/uv/) for the corpus
builder and downloads its pinned public sources once into `bench/.cache`.
Both write `bench/results/long-<host>.json` and `.md`; the `-docs` form reports
the score distribution, false positives and latency of your texts (it has no
attacks, so no detection rate). Pin cores with `taskset -c 0,1` and set
`INFERENCE_MAX_CONCURRENCY` to match, as the 2 vCPU row does.

### PDF documents

A PDF sent inline is read by the gateway (`PDF_EXTRACT`, on by default) and
its text is scanned like any long document, so a PDF costs the extraction
plus the scan of its text at the rates above. Measured with
`BenchmarkPDFDocument` (L1 only) and `BenchmarkPDFDocumentML` (the models
behind `ml.Live`, as the gateway runs them; `cmd/gateway/pdf_bench_test.go`):
a generated 100-page PDF with about 840 KB of benign text (207,629 tokens;
92 KiB of compressed PDF in base64) through the gateway to a fake upstream,
on `/v1/messages`, chat completions and `/v1/responses`, with
`MAX_SCAN_TOKENS=250000` and `INDIRECT_ACTION=redact` so that every window
is scored, no scan cache, one request at a time, 3 requests per API shape.
Apple M3 Max (14 cores, 36 GB), macOS 15.4.1, Go 1.26, commit e637c60,
2026-11-11, local and indicative. Every number here is measured; nothing is
estimated.

| Step | L1 only | With the models (L1+L2 on 256-token windows, `INFERENCE_INTRA_OP_THREADS=1`) |
|---|---:|---:|
| Extract the text (PDFium in wazero) | 0.65 to 1.1 s | 0.95 to 1.2 s |
| Whole request (extract, sanitize, scan, forward) | 0.93 to 1.6 s | 41.5 to 47.2 s |
| Windows scored | 479 chunks of 2 KiB, 0 skipped | 1,093 windows, 0 skipped |
| Peak RSS growth over the 3 requests | 0.2 MB | 95 MB |
| Redacted (benign document taken for an injection) | 0 of 3 | 0 of 3 |

- The three API shapes give the same numbers within noise (with the models 41.5 s on `/v1/responses`, 45.8 s on `/v1/messages`, 47.2 s on chat completions; L1 only 1.52 to 1.61 s);
  the table shows `/v1/messages`.
- Cold start: compiling the PDFium WebAssembly module took 1.5 to 2.4 s and
  the first document through a fresh runtime 0.66 to 1.1 s, with 50 to 150 MB
  of resident memory for the runtime. The gateway compiles the module in the
  background at start-up (`/readyz` does not wait for it), so a request pays
  it only when it arrives before the compile is done.
- The scan dominates: extraction is 2 to 3% of the request with the models.
  The scan ran at about 4,500 tokens/s: the large-input lane's default of
  `INFERENCE_LARGE_MAX_CONCURRENCY` = CPUs / 4 (3 here) model runs at once,
  against K = 4 in the long-input table above; raise it to scan one document
  faster. On 2 to 4 cloud vCPUs expect 3 to 4 times longer per core, as that
  table says: a 200k-token PDF is minutes, not seconds, there.
- Run-to-run spread on this laptop was large (extraction 0.65 s in one run
  and 1.1 s in another, the same code and document); read every figure as a
  range, as the ones above are written.
- Memory: each document is parsed in a fresh PDFium instance whose linear
  memory (up to `PDF_EXTRACT_MEMORY`, 512 MiB) is returned afterwards; with a
  warm runtime the process grew by up to about 95 MB over the first three
  200k-token requests and not at all over the later ones (the Go runtime
  keeps the memory). Count `PDF_EXTRACT_MAX_CONCURRENCY` × `PDF_EXTRACT_MEMORY` as the
  worst case on top of the figures in "Measured resource use".
- A long benign PDF may still be blocked by the classifier (long-document
  false positives, RF-895d3533); run document-heavy applications with
  `INDIRECT_ACTION=redact` until that lands.

Reproduce (the second form needs the models and `make onnx-deps`):

```bash
go test ./cmd/gateway -run '^$' -bench 'PDFDocument$' -benchtime 3x
CGO_ENABLED=1 CGO_LDFLAGS=-L$PWD/.onnx/lib ONNXRUNTIME_LIB=$PWD/.onnx/lib/libonnxruntime.dylib \
  go test -tags onnx ./cmd/gateway -run '^$' -bench 'PDFDocumentML' -benchtime 3x
```

## Disk

- Models: about 135 MB (light) or 270 MB (full) per version kept, plus older
  versions you pulled for rollback.
- Images (unpacked, arm64): gateway 285 MB, control plane 46 MB, Postgres
  415 MB, Caddy 88 MB.
- Postgres: the audit table grows with every request. Measured on the stack
  above: 20,020 rows took 7.4 MB with indexes, about **380 bytes per request**
  with the default `AUDIT_STORE_CONTENT=false` (hashes and lengths only).
  1 million requests a day kept for the default 90 days
  (`AUDIT_RETENTION_DAYS`) is about 34 GB. Storing content adds the size of
  every prompt and response.
- Logs: the production compose keeps at most 50 MB per container.

## Measure on your hardware

```bash
# 1. a key (see the README quick start), then a body like your traffic
cat > body.json <<'EOF'
{"model":"m","messages":[{"role":"user","content":"<a prompt of typical length>"}]}
EOF
# 2. load, while watching the containers
ab -n 5000 -c 8 -p body.json -T application/json -H "x-api-key: $KEY" \
  http://localhost:8080/v1/chat/completions
docker stats    # in another terminal
# 3. audit table size per row
docker compose exec postgres psql -U ps -d guardspec -c \
  "SELECT count(*), pg_size_pretty(pg_total_relation_size('requests')) FROM requests"
```

Run it without `UPSTREAM_LLM_URL` (stub answers) to see the guard alone, and
once per `DETECTOR_LAYERS` value you consider. Reports with other hardware
are welcome in an issue.
