# syntax=docker/dockerfile:1
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# gateway-full: the released gateway image with its models baked in, for
# air-gapped installs (no `models pull`, no /models mount). It adds:
#
#   L2  guardspec-classifier-v3b  /models/local/guardspec-classifier-v3b/
#       model_int8.onnx, tokenizer.json, config.json, thresholds.json,
#       calibration.json; checked against build/gateway-full.l2.sha256.
#   L3  multilingual-e5-small     /models/cache/multilingual-e5-small/
#       pulled by the image's own `models` tool from its manifest.yaml, which
#       pins a Hugging Face commit and the SHA-256 of every file.
#
# Build (the L2 files come from a named build context, a directory holding
# them; CI fills it with `go run ./cmd/models pull`, see release.yml):
#
#   docker buildx build -f build/gateway-full.Dockerfile \
#     --build-arg GATEWAY_IMAGE=ghcr.io/guard-spec/guard-spec-gateway:<version> \
#     --build-context l2=<dir with the five L2 files> \
#     -t guard-spec-gateway-full:<version> .
#
# The models are owned by root and read-only; the gateway runs as the same
# non-root user as the gateway image (nobody). Only the L3 pull needs network,
# at build time; the image itself needs none.

# The gateway image to extend: a released tag or digest, or a local build of
# build/gateway.Dockerfile (docker-compose.yml tags it guard-spec-gateway:latest;
# pass --build-arg GATEWAY_IMAGE=guard-spec-gateway:latest to use it). The
# default is the signed v0.4.2 release, pinned by the digest of its index, so a
# build without the argument never pulls a moving tag. The release workflow
# always passes the digest of the gateway image it has just built and signed.
ARG GATEWAY_IMAGE=ghcr.io/guard-spec/guard-spec-gateway:0.4.2@sha256:35ccc18c629f371945209b27c57ef5542d8d5c70f16fd157faf42795f107d2e7

# Default for the `l2` build context: empty, so a build without
# --build-context l2=... stops below with a clear message.
FROM scratch AS l2

FROM ${GATEWAY_IMAGE} AS gateway

# The gateway image has no shell (distroless), so the models are assembled in
# a Debian stage that is not shipped: it runs the image's own models tool and
# manifest, with the image's CA certificates.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS models
WORKDIR /app
COPY --from=gateway /app/models /app/manifest.yaml ./
COPY --from=gateway /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY build/gateway-full.l2.sha256 /tmp/l2.sha256
COPY --from=l2 / /tmp/l2/
# L2: exactly the files listed in build/gateway-full.l2.sha256, each verified.
RUN set -eu; \
    dest=/models/local/guardspec-classifier-v3b; \
    if [ ! -s /tmp/l2/model_int8.onnx ]; then \
      echo "gateway-full: no L2 model. Pass --build-context l2=<dir> with the files of build/gateway-full.l2.sha256." >&2; \
      exit 1; \
    fi; \
    (cd /tmp/l2 && sha256sum --strict -c /tmp/l2.sha256); \
    mkdir -p "$dest"; \
    awk '{print $2}' /tmp/l2.sha256 | while read -r f; do cp "/tmp/l2/$f" "$dest/$f"; done; \
    rm -rf /tmp/l2 /tmp/l2.sha256
# L3: the image's own models tool and manifest (SHA-256 verified). It pulls into
# a scratch directory and the model directory is moved into place, so the
# result does not depend on the tool's cache layout.
RUN set -eu; \
    ./models pull -manifest manifest.yaml -models multilingual-e5-small -dir /tmp/pull; \
    src=$(dirname "$(find /tmp/pull -name model.onnx -path '*multilingual-e5-small*' | head -n 1)"); \
    test -f "$src/tokenizer.json" && test -f "$src/config.json"; \
    mkdir -p /models/cache; \
    mv "$src" /models/cache/multilingual-e5-small; \
    rm -rf /tmp/pull; \
    find /models/cache/multilingual-e5-small -name '.*' -exec rm -rf {} +; \
    chown -R root:root /models; \
    chmod -R a=rX /models; \
    ls -lR /models

FROM ${GATEWAY_IMAGE}
COPY --from=models /models /models
# Explicit model directories: they work whether the gateway resolves L2 from
# L2_MODEL_DIR or from L2_MODEL=name@version. DETECTOR_REQUIRE_ML=true: the
# models are in the image, so a layer that fails to load is an error, not a
# silent fall back to L1 (GUARD_ENV=dev turns that into a warning).
ENV MODEL_DIR=/models \
    L2_MODEL_DIR=/models/local/guardspec-classifier-v3b \
    L3_MODEL_DIR=/models/cache/multilingual-e5-small \
    DETECTOR_LAYERS=l1,l2,l3 \
    DETECTOR_REQUIRE_ML=true
USER nobody
