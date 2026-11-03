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

# --- dist: the linux onnx tarball of a release (.github/workflows/release.yml) ---
# docker buildx build --target dist --output type=local,dest=out ...
# Same binary as the image; it needs glibc >= 2.36 (Debian 12) at run time and
# ONNXRUNTIME_LIB pointing at the bundled libonnxruntime.so.
FROM scratch AS dist
COPY --from=builder /out/gateway /out/models /
COPY --from=builder /opt/onnx/lib/libonnxruntime.so /lib/
COPY --from=builder /opt/onnx/LICENSE.onnxruntime /src/LICENSE /src/NOTICE /src/THIRD_PARTY_LICENSES.md /src/models/manifest.yaml /

# --- runtime image (default target) ---
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# ONNX Runtime CPU shared library (MIT), loaded by internal/onnx via dlopen.
COPY --from=builder /opt/onnx/lib/libonnxruntime.so /usr/local/lib/
COPY --from=builder /opt/onnx/LICENSE.onnxruntime /usr/share/doc/onnxruntime/LICENSE
# Model files are mounted at /models (read-only is fine), never baked in. An
# empty /models: the gateway warns and runs L1 only; /readyz shows the layers.
ENV ONNXRUNTIME_LIB=/usr/local/lib/libonnxruntime.so \
    MODEL_DIR=/models

WORKDIR /app
COPY --from=builder /out/gateway /out/onnxbench /out/models ./
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/models/manifest.yaml ./manifest.yaml
COPY --from=builder /src/LICENSE /src/NOTICE /src/THIRD_PARTY_LICENSES.md /usr/share/doc/guard-spec/

EXPOSE 8080 9090
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s CMD curl -fsS http://localhost:8080/readyz || exit 1

USER nobody
ENTRYPOINT ["./gateway"]
