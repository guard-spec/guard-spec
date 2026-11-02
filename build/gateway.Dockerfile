# syntax=docker/dockerfile:1
# Gateway: Go data plane with ONNX Runtime

FROM golang:1.22-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# ORT shared lib path must be available at build time
ARG ORT_LIB_DIR=/usr/local/lib
RUN CGO_ENABLED=1 GOOS=linux \
    go build -tags ORT -ldflags="-s -w" \
    -o /out/gateway ./cmd/gateway/

# --- runtime image ---
FROM debian:bookworm-slim

# ORT runtime dependency
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Install ORT shared library (CPU, 1.18.x)
ARG ORT_VERSION=1.18.1
RUN ORT_ARCH=$(uname -m | sed 's/x86_64/x64/') \
    && curl -fsSL \
    "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-${ORT_ARCH}-${ORT_VERSION}.tgz" \
    | tar -xz -C /usr/local/lib --strip-components=2 \
    && ldconfig

WORKDIR /app
COPY --from=builder /out/gateway .
COPY --from=builder /src/migrations ./migrations

EXPOSE 8080 9090
HEALTHCHECK --interval=10s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1

USER nobody
ENTRYPOINT ["./gateway"]
