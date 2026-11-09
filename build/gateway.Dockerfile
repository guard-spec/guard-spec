# syntax=docker/dockerfile:1
# Gateway: Go data plane with in-process ONNX Runtime (internal/onnx).
#
# Builds for linux/amd64 and linux/arm64 (docker buildx --platform ...).
# The `onnx` build tag needs cgo: libtokenizers.a is linked statically and
# libonnxruntime.so is shipped in the image and loaded at run time
# (ONNXRUNTIME_LIB). Versions and SHA-256 values live in build/onnx-deps.sh.

# Default for the `onnx-cache` build context: empty. CI passes
#   --build-context onnx-cache=<dir> --build-arg ONNX_DEPS_CACHE=/onnx-cache
# with the archives from actions/cache, so a GitHub Releases outage does not
# fail the build; onnx-deps.sh still checks every SHA-256. Releases and local
# builds pass neither and download as before.
FROM scratch AS onnx-cache

FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS builder
ARG TARGETOS=linux
ARG TARGETARCH
# Release version, linked into the binaries (gateway --version).
ARG VERSION=dev

WORKDIR /src
COPY build/onnx-deps.sh /tmp/onnx-deps.sh
ARG ONNX_DEPS_CACHE
RUN --mount=type=bind,from=onnx-cache,target=/onnx-cache \
    sh /tmp/onnx-deps.sh /opt/onnx "$TARGETOS" "${TARGETARCH:-$(uname -m)}"

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ENV CGO_ENABLED=1 CGO_LDFLAGS=-L/opt/onnx/lib GOTOOLCHAIN=local
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -tags onnx -trimpath -ldflags="-s -w -X github.com/guard-spec/guard-spec/internal/version.Version=${VERSION#v}" -o /out/gateway ./cmd/gateway/ \
 && go build -tags onnx -trimpath -ldflags="-s -w" -o /out/onnxbench ./cmd/onnxbench/ \
 && go build -trimpath -ldflags="-s -w -X github.com/guard-spec/guard-spec/internal/version.Version=${VERSION#v}" -o /out/models ./cmd/models/ \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/guard-spec/guard-spec/internal/version.Version=${VERSION#v}" -o /out/doctor ./cmd/doctor/

# --- dist: the linux onnx tarball of a release (.github/workflows/release.yml) ---
# docker buildx build --target dist --output type=local,dest=out ...
# Same binary as the image; it needs glibc >= 2.36 (Debian 12) at run time and
# ONNXRUNTIME_LIB pointing at the bundled libonnxruntime.so.
FROM scratch AS dist
COPY --from=builder /out/gateway /out/models /out/doctor /
COPY --from=builder /opt/onnx/lib/libonnxruntime.so /lib/
COPY --from=builder /opt/onnx/LICENSE.onnxruntime /src/LICENSE /src/NOTICE /src/THIRD_PARTY_LICENSES.md /src/models/manifest.yaml /

# --- runtime image (default target) ---
# Chainguard glibc-dynamic (Wolfi): glibc, libgcc, libstdc++ and CA
# certificates only, rebuilt daily with fixes; no shell, package manager or
# curl. Debian bookworm-slim carried hundreds of OS CVEs without a fix; this
# base has none at the pinned digest (Dependabot bumps it). The binaries are
# built on Debian 12 (glibc 2.36) and run on the newer glibc of Wolfi. The
# HEALTHCHECK, compose and Kubernetes use the binaries' own subcommands
# (gateway health, models init, doctor copy-migrations) instead of scripts.
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:aab5cd0b4cc5edd9c87b6e7aa9ddaa3fb6ffcec559b9e5473c55bbc937b65399

# ONNX Runtime CPU shared library (MIT), loaded by internal/onnx via dlopen.
COPY --from=builder /opt/onnx/lib/libonnxruntime.so /usr/local/lib/
COPY --from=builder /opt/onnx/LICENSE.onnxruntime /usr/share/doc/onnxruntime/LICENSE
# Model files are mounted at /models (read-only is fine), never baked in. An
# empty /models: the gateway warns and runs L1 only; /readyz shows the layers.
ENV ONNXRUNTIME_LIB=/usr/local/lib/libonnxruntime.so \
    MODEL_DIR=/models

WORKDIR /app
COPY --from=builder /out/gateway /out/onnxbench /out/models /out/doctor ./
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/models/manifest.yaml ./manifest.yaml
COPY --from=builder /src/LICENSE /src/NOTICE /src/THIRD_PARTY_LICENSES.md /usr/share/doc/guard-spec/

EXPOSE 8080 9090
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s CMD ["/app/gateway", "health"]

USER nobody
ENTRYPOINT ["./gateway"]
