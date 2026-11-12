# syntax=docker/dockerfile:1
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Gateway, GPU option, linux/amd64 only. This image is not published: build
# it yourself (below) and push it to your own registry. CI builds it on every
# pull request (not pushed) to keep this file working.
#
# The CPU image (build/gateway.Dockerfile) stays the default and is not
# changed by this file. This image runs the same gateway binary, built the
# same way, with ONNX Runtime's CUDA 12 build (CUDA execution provider) on
# NVIDIA's CUDA 12 + cuDNN 9 runtime base, and INFERENCE_PROVIDER=cuda: on a
# host without a usable GPU the gateway stops at start with an error that
# says so (set INFERENCE_PROVIDER=auto to fall back to the CPU instead).
# It needs an NVIDIA GPU with driver 525 or newer and the NVIDIA container
# runtime (docker run --gpus all, or the Kubernetes device plugin:
# deploy/helm/guard-spec gateway.gpu.enabled).
#
#   docker build --platform linux/amd64 -f build/gateway-gpu.Dockerfile -t <registry>/guard-spec-gateway:<version>-gpu .
#
# The base image carries NVIDIA's CUDA and cuDNN runtime libraries; by
# building and using it you accept NVIDIA's license terms for them (NOTICE).
# The result is about 5.7 GB unpacked.
# Models are mounted at /models as for the CPU image; the GPU loads
# model_fp16.onnx (`models pull -provider cuda`), else the INT8 model.

# Default for the `onnx-cache` build context: empty (see build/gateway.Dockerfile).
FROM scratch AS onnx-cache

FROM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS builder
# Release version, linked into the binaries (gateway --version).
ARG VERSION=dev

WORKDIR /src
COPY build/onnx-deps.sh /tmp/onnx-deps.sh
ARG ONNX_DEPS_CACHE
RUN --mount=type=bind,from=onnx-cache,target=/onnx-cache \
    sh /tmp/onnx-deps.sh /opt/onnx linux amd64 gpu

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ENV CGO_ENABLED=1 CGO_LDFLAGS=-L/opt/onnx/lib GOTOOLCHAIN=local
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -tags onnx -trimpath -ldflags="-s -w -X github.com/guard-spec/guard-spec/internal/version.Version=${VERSION#v}" -o /out/gateway ./cmd/gateway/ \
 && go build -tags onnx -trimpath -ldflags="-s -w" -o /out/onnxbench ./cmd/onnxbench/ \
 && go build -trimpath -ldflags="-s -w -X github.com/guard-spec/guard-spec/internal/version.Version=${VERSION#v}" -o /out/models ./cmd/models/ \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/guard-spec/guard-spec/internal/version.Version=${VERSION#v}" -o /out/doctor ./cmd/doctor/

# --- runtime image ---
# nvidia/cuda 12.9.2 with cuDNN 9, runtime flavour (no compilers), Ubuntu
# 24.04, by digest of the multi-arch index (Dependabot bumps it). It sets
# NVIDIA_VISIBLE_DEVICES=all and NVIDIA_DRIVER_CAPABILITIES=compute,utility,
# so the NVIDIA runtime mounts the driver and nvidia-smi.
FROM nvidia/cuda:12.9.2-cudnn-runtime-ubuntu24.04@sha256:070f8f2672df1b05b84c0409a5fd1d54ddfd646e5b9d8dee7878131271b563fc

# ONNX Runtime GPU (MIT): libonnxruntime.so and its CUDA provider, which it
# loads from the same directory. Loaded by internal/onnx via dlopen.
COPY --from=builder /opt/onnx/lib/libonnxruntime.so /opt/onnx/lib/libonnxruntime_providers_cuda.so \
     /opt/onnx/lib/libonnxruntime_providers_shared.so /opt/onnx/lib/VERSION.onnxruntime /usr/local/lib/onnxruntime/
COPY --from=builder /opt/onnx/LICENSE.onnxruntime /usr/share/doc/onnxruntime/LICENSE
COPY --from=builder /opt/onnx/ThirdPartyNotices.onnxruntime.txt /usr/share/doc/onnxruntime/ThirdPartyNotices.txt
ENV ONNXRUNTIME_LIB=/usr/local/lib/onnxruntime/libonnxruntime.so \
    MODEL_DIR=/models \
    INFERENCE_PROVIDER=cuda

WORKDIR /app
COPY --from=builder /out/gateway /out/onnxbench /out/models /out/doctor ./
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/models/manifest.yaml ./manifest.yaml
COPY --from=builder /src/LICENSE /src/NOTICE /src/THIRD_PARTY_LICENSES.md /usr/share/doc/guard-spec/

EXPOSE 8080 9090
HEALTHCHECK --interval=10s --timeout=3s --start-period=60s CMD ["/app/gateway", "health"]

USER nobody
ENTRYPOINT ["./gateway"]
