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
