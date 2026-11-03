# syntax=docker/dockerfile:1
# Gateway: Go data plane with in-process ONNX Runtime (internal/onnx).
#
# Builds for linux/amd64 and linux/arm64 (docker buildx --platform ...).
# The `onnx` build tag needs cgo: libtokenizers.a is linked statically and
# libonnxruntime.so is shipped in the image and loaded at run time
# (ONNXRUNTIME_LIB). Versions and SHA-256 values live in build/onnx-deps.sh.

FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS builder
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src
COPY build/onnx-deps.sh /tmp/onnx-deps.sh
RUN sh /tmp/onnx-deps.sh /opt/onnx "$TARGETOS" "${TARGETARCH:-$(uname -m)}"

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ENV CGO_ENABLED=1 CGO_LDFLAGS=-L/opt/onnx/lib GOTOOLCHAIN=local
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -tags onnx -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway/ \
 && go build -tags onnx -trimpath -ldflags="-s -w" -o /out/onnxbench ./cmd/onnxbench/ \
 && go build -trimpath -ldflags="-s -w" -o /out/models ./cmd/models/

# --- runtime image ---
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# ONNX Runtime CPU shared library (MIT), loaded by internal/onnx via dlopen.
COPY --from=builder /opt/onnx/lib/libonnxruntime.so /usr/local/lib/
COPY --from=builder /opt/onnx/LICENSE.onnxruntime /usr/share/doc/onnxruntime/LICENSE
ENV ONNXRUNTIME_LIB=/usr/local/lib/libonnxruntime.so \
    MODELS_PATH=/models

WORKDIR /app
COPY --from=builder /out/gateway /out/onnxbench /out/models ./
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/models/manifest.yaml ./manifest.yaml

EXPOSE 8080 9090
HEALTHCHECK --interval=10s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1

USER nobody
ENTRYPOINT ["./gateway"]
