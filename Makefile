.PHONY: build test lint vuln fuzz bench docker-build docker-up docker-down migrate-up migrate-down

GO      := go

# L1-only binaries (no cgo). For the model layers see onnx-deps / test-onnx below.
build:
	$(GO) build -o bin/gateway ./cmd/gateway
	$(GO) build -o bin/control-plane ./cmd/control-plane

test:
	$(GO) test -race ./...

lint:
	golangci-lint run ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Third-party Go licenses, including the cgo modules of the onnx build. v1 of
# go-licenses fails on the standard library of current Go releases, hence v2.
GO_LICENSES     := github.com/google/go-licenses/v2@v2.0.1
LICENSES_ENV    := GOFLAGS=-tags=onnx CGO_ENABLED=1
# GPL, AGPL and LGPL are "forbidden" or "restricted" in go-licenses' classes.
LICENSES_DENIED := forbidden,restricted,unknown

.PHONY: licenses licenses-check
licenses:           ## write THIRD_PARTY_LICENSES.md
	$(LICENSES_ENV) $(GO) run $(GO_LICENSES) report ./... --ignore github.com/guard-spec/guard-spec --template build/licenses.md.tpl > THIRD_PARTY_LICENSES.md

licenses-check:     ## fail on GPL/AGPL/LGPL or unknown licenses
	$(LICENSES_ENV) $(GO) run $(GO_LICENSES) check ./... --disallowed_types=$(LICENSES_DENIED)

FUZZTIME ?= 30s
fuzz:
	$(GO) test ./internal/sanitizer/ -run NONE -fuzz FuzzSanitize -fuzztime $(FUZZTIME)
	$(GO) test ./internal/policy/ -run NONE -fuzz FuzzJSONASTToCEL -fuzztime $(FUZZTIME)
	$(GO) test ./internal/policy/ -run NONE -fuzz FuzzValidateRules -fuzztime $(FUZZTIME)
	$(GO) test ./internal/policy/ -run NONE -fuzz FuzzParseCondition -fuzztime $(FUZZTIME)
	$(GO) test ./cmd/gateway/ -run NONE -fuzz FuzzChatRequest -fuzztime $(FUZZTIME)

# Go benchmarks (README, "Benchmarks"): input sanitizer, output guard, CEL
# policy evaluation and the gateway's HTTP path end to end with L1 only (no
# models, no cgo). bench-onnx adds the HTTP path with L1+L2+L3 and L1+L2.
BENCH_PKGS := ./internal/sanitizer ./internal/outputguard ./internal/policy ./cmd/gateway
BENCHTIME  ?= 1s
bench:
	$(GO) test -run '^$$' -bench . -benchmem -benchtime $(BENCHTIME) $(BENCH_PKGS)

docker-build:
	docker build -f build/gateway.Dockerfile    -t guard-spec-gateway:latest .
	docker build -f build/control-plane.Dockerfile -t guard-spec-control-plane:latest .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

migrate-up:
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path migrations -database "$(DATABASE_URL)" down 1

# --- in-process ONNX (internal/onnx, docs/adr/0001-onnx-runtime.md) ---
ONNX_DIR  := $(CURDIR)/.onnx
ONNX_ENV  := CGO_ENABLED=1 CGO_LDFLAGS=-L$(ONNX_DIR)/lib ONNXRUNTIME_LIB=$(ONNX_DIR)/lib/libonnxruntime$(if $(filter Darwin,$(shell uname -s)),.dylib,.so)

.PHONY: onnx-deps models-pull test-onnx bench-onnx onnxbench eval-ml calibrate

onnx-deps: $(ONNX_DIR)/lib/libtokenizers.a   ## fetch libonnxruntime + libtokenizers.a into .onnx/lib

$(ONNX_DIR)/lib/libtokenizers.a: build/onnx-deps.sh
	sh build/onnx-deps.sh $(ONNX_DIR)
	touch $@

models-pull:        ## download + verify models/manifest.yaml into models/cache
	$(GO) run ./cmd/models pull -dir models/cache

test-onnx: onnx-deps
	$(ONNX_ENV) $(GO) test -race -tags onnx ./...

# Eval with the model layers (L1+L2+L3, see internal/inference/ml) against
# eval/baseline-onnx.json. LAYERS=l1,l2 CASCADE=1 for other configurations.
eval-ml: onnx-deps
	$(ONNX_ENV) $(GO) run -tags onnx ./cmd/eval -detector fusion-ml \
	  $(if $(LAYERS),-layers $(LAYERS)) $(if $(CASCADE),-cascade) \
	  $(if $(LAYERS)$(CASCADE),,-baseline eval/baseline-onnx.json)

# Refit the L2/L3 calibration and compare fusion methods on train/data/val.jsonl
# (never eval/); writes calibration.json next to the classifier.
calibrate: onnx-deps
	$(ONNX_ENV) $(GO) run -tags onnx ./cmd/calibrate fit -write

# BenchmarkGatewayHTTPML: needs models/ (or MODEL_DIR); skips without them.
bench-onnx: onnx-deps
	$(ONNX_ENV) $(GO) test -tags onnx -run '^$$' -bench 'GatewayHTTPML|ConversationWindowML' -benchmem -benchtime $(BENCHTIME) ./cmd/gateway

# Public benchmark against other detectors (docs/benchmark.md, bench/run.py):
# public datasets at pinned revisions and models into BENCH_CACHE, results into
# bench/results and the generated block of docs/benchmark.md. Needs uv.
# PROMPTGUARD=1 adds Meta Prompt Guard 2 (gated: your own HF_TOKEN).
BENCH_CACHE ?= $(CURDIR)/bench/.cache
.PHONY: benchmark
benchmark: onnx-deps
	$(ONNX_ENV) BENCH_CACHE=$(BENCH_CACHE) uv run --project bench --frozen $(if $(PROMPTGUARD),--extra promptguard) \
	  python bench/run.py --update-doc docs/benchmark.md $(if $(PROMPTGUARD),--promptguard)

onnxbench: onnx-deps
	$(ONNX_ENV) $(GO) run -tags onnx ./cmd/onnxbench -model models/local/guardspec-classifier-v3b
