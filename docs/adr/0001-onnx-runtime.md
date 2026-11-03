# ADR 0001: ONNX runtime for in-process inference

- Status: accepted
- Date: 2026-11-04
- Task: RF-3e103645 (N2)

## Context

Guard Spec runs transformer classifiers (prompt-injection) and sentence
embedders in the gateway process, without a Python service. We need a Go
binding to ONNX Runtime (ORT) and a tokenizer that produces exactly the ids the
Hugging Face tokenizer produces, on macOS arm64 (dev) and linux amd64/arm64
(Docker), under licenses compatible with Apache-2.0.

## Options

| | hugot v0.8.5 (ORT backend) | hugot (pure-Go / GoMLX backend) | **yalue/onnxruntime_go v1.38 + daulet/tokenizers v1.27** |
|---|---|---|---|
| License | Apache-2.0 | Apache-2.0 | MIT + MIT (ORT: MIT, HF tokenizers: Apache-2.0) |
| Go version | **go 1.27** in go.mod | same | go 1.19 / 1.21 (repo is on 1.22) |
| Dependencies | GoMLX, go-xla, onnx-gomlx, ortgenai, x/sync 0.24, x/text 0.43, … | same | none beyond cgo |
| Tokenizer | daulet/tokenizers (Rust) or pure-Go | pure-Go (sentencepiece/WordPiece re-implementations) | HF Rust `tokenizers` itself |
| HF parity | exact with the Rust tokenizer | not guaranteed (Unigram/XLM-R normalisers re-implemented) | exact by construction; checked by a golden test |
| Platforms | same as ORT | any, but much slower on CPU | ORT ships darwin-arm64, linux-x64, linux-aarch64; daulet ships matching `libtokenizers.a` |
| Size | large dep tree | large | +~16 MB to a static binary (tokenizer), libonnxruntime.so ≈ 20 MB (linux) |

Licenses were checked on the repositories (GitHub license API, 2026-11-04):

- https://github.com/yalue/onnxruntime_go/blob/master/LICENSE (MIT)
- https://github.com/daulet/tokenizers/blob/main/LICENSE (MIT); it statically
  links https://github.com/huggingface/tokenizers (Apache-2.0)
- https://github.com/microsoft/onnxruntime/blob/main/LICENSE (MIT)
- https://github.com/knights-analytics/hugot/blob/main/LICENSE (Apache-2.0)

## Decision

Use **github.com/yalue/onnxruntime_go** with **github.com/daulet/tokenizers**,
wrapped in `internal/onnx`.

- hugot's current release requires Go 1.27 and pulls a large ML stack (GoMLX,
  XLA bindings) plus newer `golang.org/x/*` versions. Adopting it would force a
  toolchain and dependency upgrade on the whole repo for features we do not
  use (pipelines, training, generative models). Its ORT backend is the same
  two libraries we chose, so we lose nothing on speed or parity.
- The pure-Go backend avoids cgo but re-implements tokenizers and kernels; it
  is slower on CPU and parity with Hugging Face is not guaranteed, which
  matters for a security classifier.
- daulet/tokenizers is the Hugging Face Rust library behind a C ABI, so ids
  match `transformers` exactly (verified against Python `tokenizers` 0.23.3 on
  English, Vietnamese, CJK, emoji and markup inputs, see
  `internal/onnx/testdata/*.golden.json`).
- onnxruntime_go loads `libonnxruntime` with dlopen at run time, so the Go
  build only needs cgo, not ORT headers or link flags; the library path is set
  with `ONNXRUNTIME_LIB`.

## Consequences

- The real backend needs `CGO_ENABLED=1`, the build tag `onnx`, and
  `CGO_LDFLAGS=-L<dir with libtokenizers.a>`. `build/onnx-deps.sh` fetches
  ORT 1.31.1 and libtokenizers 1.27.0 with pinned SHA-256 for darwin-arm64,
  linux-amd64 and linux-arm64. Without the tag a stub is compiled and the
  constructors return `ErrUnavailable`, so `go build ./...` and `go test ./...`
  work with or without cgo.
- onnxruntime_go is tied to an ORT C API version (v1.38 ↔ API 31, ORT 1.31.x);
  upgrades must move both together.
- Musl (Alpine) images would need the musl `libtokenizers.a` and an ORT build
  for musl; we use Debian (glibc) images.

## Usage

```sh
make onnx-deps                       # .onnx/lib: libonnxruntime + libtokenizers.a
go run ./cmd/models pull             # models/cache/<name>/{model.onnx,tokenizer.json,config.json}
make test-onnx                       # integration tests (tag onnx)
make onnxbench                       # latency table
```

Run time: `ONNXRUNTIME_LIB` (path to libonnxruntime; the image sets
`/usr/local/lib/libonnxruntime.so`), `INFERENCE_MAX_CONCURRENCY` (default: CPU
count), `INFERENCE_INTRA_OP_THREADS` (default: `min(4, NumCPU)` on Linux,
ORT's own choice elsewhere; `0` forces ORT's choice). On the M3 Max the ORT
default beat 3 threads; in the linux/arm64 container the ORT default (one
spinning thread per core) was 3-7x slower than 4 threads, hence the split.
`HF_TOKEN` is needed to pull the gated ProtectAI small v2 model.

## Measurements (2026-11-04, `cmd/onnxbench`, one text per request, n=100)

Apple M3 Max (10P+4E), macOS, ORT 1.31.1, default threads. The ProtectAI
*small* v2 repo is gated and no token was available, so the classifier numbers
are for the *base* v2 model (same labels and tokenizer, ~3x the compute of
small); small should be markedly faster.

| model | tokens | conc | p50 ms | p99 ms | req/s |
|---|---:|---:|---:|---:|---:|
| deberta-v3-base-pi-v2 (fp32) | 64 | 1 | 24.9 | 26.8 | 40.0 |
| | 64 | 4 | 56.8 | 68.1 | 72.0 |
| | 256 | 1 | 94.9 | 117.8 | 10.4 |
| | 256 | 4 | 244.7 | 314.9 | 16.1 |
| | 512 | 1 | 229.2 | 282.0 | 4.3 |
| | 512 | 4 | 633.9 | 742.9 | 6.2 |
| multilingual-e5-small (int8) | 64 | 1 | 4.4 | 5.4 | 227.7 |
| | 64 | 4 | 7.6 | 9.3 | 512.5 |
| | 256 | 1 | 13.8 | 39.3 | 65.3 |
| | 256 | 4 | 32.5 | 37.1 | 125.0 |
| | 512 | 1 | 29.3 | 41.0 | 33.6 |
| | 512 | 4 | 79.2 | 91.1 | 50.1 |

linux/arm64 container (`guardspec-onnx-dev:arm64` built from
build/gateway.Dockerfile) on the same Mac under Docker Desktop, 14 vCPUs shared
with other running stacks, default threads (4):

| model | tokens | conc | p50 ms | p99 ms | req/s |
|---|---:|---:|---:|---:|---:|
| deberta-v3-base-pi-v2 (fp32) | 64 | 1 | 84.3 | 177.6 | 11.5 |
| | 64 | 4 | 128.2 | 170.0 | 30.7 |
| | 256 | 1 | 288.8 | 500.9 | 3.9 |
| | 256 | 4 | 508.2 | 694.9 | 7.8 |
| | 512 | 1 | 509.4 | 779.2 | 2.0 |
| | 512 | 4 | 896.7 | 961.0 | 4.4 |
| multilingual-e5-small (int8) | 64 | 1 | 5.8 | 6.6 | 173.7 |
| | 64 | 4 | 9.4 | 10.0 | 419.4 |
| | 256 | 1 | 18.4 | 20.3 | 54.4 |
| | 256 | 4 | 40.2 | 44.9 | 99.0 |
| | 512 | 1 | 42.5 | 53.7 | 23.2 |
| | 512 | 4 | 105.1 | 122.2 | 37.9 |

The fp32 DeBERTa is 3-4x slower in the container than natively (the int8 e5
only ~1.3x), so the fp32 classifier, not the runtime, dominates; an int8
export of the small model is the obvious next step for the hot path.

linux/amd64: the image also builds (`--platform linux/amd64`) and runs under
Docker Desktop's x86 emulation (base classifier, 64 tokens: p50 83 ms), which
proves the binary and library load; the latency is not representative of real
amd64 hardware.

Observation: ProtectAI flags highly repetitive benign text (one sentence
repeated 20 times scores INJECTION ≈ 0.98 in a single window); varied long
prose scores ≈ 0. Callers should not treat repetition-only hits as certain.

## Addendum: guardspec-classifier-v0 as L2

Our own classifier (PR #9, `models/local/guardspec-classifier-v0/`:
`model_int8.onnx`, 8-label sigmoid head, risk = 1 − p(benign)) replaces
ProtectAI as L2; the ProtectAI entries in the manifest are optional baselines.
`Classifier` picks softmax or sigmoid from config.json `problem_type`
(`multi_label_classification` → sigmoid), loads `model_int8.onnx` when there
is no `model.onnx`, takes the window size from `thresholds.json` `max_len`
(256), and `Risk()` returns 1 − p(benign). Over several windows the benign
label takes its minimum and every attack label its maximum.

macOS (M3 Max), one text per request, n=100 (512 tokens = 3 windows of 256):

| tokens | conc | p50 ms | p99 ms | req/s |
|---:|---:|---:|---:|---:|
| 64 | 1 | 4.1 | 6.0 | 235.7 |
| 64 | 4 | 7.9 | 9.0 | 499.1 |
| 256 | 1 | 13.8 | 14.8 | 72.5 |
| 256 | 4 | 31.5 | 61.7 | 123.5 |
| 512 | 1 | 34.2 | 35.8 | 29.1 |
| 512 | 4 | 84.7 | 95.3 | 47.2 |

Observed: long varied business prose (≈ 600 tokens) reaches risk 0.61
(jailbreak 0.58 in one window), below the 0.73 block threshold but above the
0.014 review threshold; worth a look in the next training round.
