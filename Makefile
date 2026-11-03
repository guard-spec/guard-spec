.PHONY: build test lint docker-build docker-up models-download

GO      := go
GOFLAGS := -tags ORT

build:
	$(GO) build $(GOFLAGS) ./cmd/gateway/...
	$(GO) build $(GOFLAGS) ./cmd/control-plane/...

test:
	$(GO) test $(GOFLAGS) ./...

lint:
	golangci-lint run ./...

docker-build:
	docker build -f build/gateway.Dockerfile    -t promptshield/gateway:latest .
	docker build -f build/control-plane.Dockerfile -t promptshield/control-plane:latest .
	docker build -f build/ui.Dockerfile         -t promptshield/ui:latest ./web

docker-up:
	docker compose up -d

docker-down:
	docker compose down

models-download:
	python cmd/model-init/download.py --models qwen3guard-0.6b,deberta-v3-xsmall-pi

migrate-up:
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path migrations -database "$(DATABASE_URL)" down 1

generate:
	$(GO) generate ./...
	protoc --go_out=. --go-grpc_out=. api/proto/*.proto

# --- in-process ONNX (internal/onnx, docs/adr/0001-onnx-runtime.md) ---
ONNX_DIR  := $(CURDIR)/.onnx
ONNX_ENV  := CGO_ENABLED=1 CGO_LDFLAGS=-L$(ONNX_DIR)/lib ONNXRUNTIME_LIB=$(ONNX_DIR)/lib/libonnxruntime$(if $(filter Darwin,$(shell uname -s)),.dylib,.so)

.PHONY: onnx-deps models-pull test-onnx onnxbench

onnx-deps: $(ONNX_DIR)/lib/libtokenizers.a   ## fetch libonnxruntime + libtokenizers.a into .onnx/lib

$(ONNX_DIR)/lib/libtokenizers.a: build/onnx-deps.sh
	sh build/onnx-deps.sh $(ONNX_DIR)
	touch $@

models-pull:        ## download + verify models/manifest.yaml into models/cache
	$(GO) run ./cmd/models pull -dir models/cache

test-onnx: onnx-deps
	$(ONNX_ENV) $(GO) test -tags onnx -v ./internal/onnx/

onnxbench: onnx-deps
	$(ONNX_ENV) $(GO) run -tags onnx ./cmd/onnxbench -model models/cache/protectai-deberta-v3-base-pi-v2
