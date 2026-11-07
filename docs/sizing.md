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
