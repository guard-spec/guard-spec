# syntax=docker/dockerfile:1
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Playground proxy (cmd/playground): the public playground's backend, in
# front of a gateway. Pure Go, no cgo, no ONNX Runtime; runs as nonroot on
# distroless. See deploy/playground/README.md.
#
#   docker build -f build/playground.Dockerfile -t guard-spec-playground:local .

FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS builder
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w -X github.com/guard-spec/guard-spec/internal/version.Version=${VERSION#v}" \
    -o /out/playground ./cmd/playground/

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /out/playground /app/playground
COPY --from=builder /src/LICENSE /src/NOTICE /usr/share/doc/guard-spec/

USER nonroot
EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=3s CMD ["/app/playground", "health"]
ENTRYPOINT ["/app/playground"]
