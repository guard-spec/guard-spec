.PHONY: build test lint vuln fuzz docker-build docker-up models-download

GO      := go
GOFLAGS := -tags ORT

build:
	$(GO) build $(GOFLAGS) ./cmd/gateway/...
	$(GO) build $(GOFLAGS) ./cmd/control-plane/...

test:
	$(GO) test $(GOFLAGS) ./...

lint:
	golangci-lint run ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

FUZZTIME ?= 30s
fuzz:
	$(GO) test ./internal/sanitizer/ -run NONE -fuzz FuzzSanitize -fuzztime $(FUZZTIME)
	$(GO) test ./internal/policy/ -run NONE -fuzz FuzzJSONASTToCEL -fuzztime $(FUZZTIME)
	$(GO) test ./internal/policy/ -run NONE -fuzz FuzzValidateRules -fuzztime $(FUZZTIME)
	$(GO) test ./cmd/gateway/ -run NONE -fuzz FuzzChatRequest -fuzztime $(FUZZTIME)

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
