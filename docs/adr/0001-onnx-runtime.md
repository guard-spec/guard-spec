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
count), `INFERENCE_INTRA_OP_THREADS` (default: ORT's choice; 3 threads was
slower than the default on an M3 Max at both concurrency 1 and 4).
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

Observation: ProtectAI flags highly repetitive benign text (one sentence
repeated 20 times scores INJECTION ≈ 0.98 in a single window); varied long
prose scores ≈ 0. Callers should not treat repetition-only hits as certain.
