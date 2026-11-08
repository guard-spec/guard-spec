# syntax=docker/dockerfile:1
# Control-plane release image used by GoReleaser (.goreleaser.yaml): the static
# binary is built outside and copied in per platform. Not for local builds; see
# the other Dockerfiles in this directory. The gateway release image needs cgo
# (-tags onnx) and is built from build/gateway.Dockerfile instead.

# Chainguard static (Wolfi): CA certificates, tzdata and passwd only; no
# shell. Same nonroot user (65532) as distroless/static had.
FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9

ARG TARGETPLATFORM
ARG BINARY

WORKDIR /app
COPY ${TARGETPLATFORM}/${BINARY} /app/service
# Installation checks (cmd/doctor): /app/doctor, run from /app.
COPY ${TARGETPLATFORM}/doctor /app/doctor
COPY migrations /app/migrations
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.md /usr/share/doc/guard-spec/

EXPOSE 8081 9091
HEALTHCHECK --interval=10s --timeout=3s CMD ["/app/service", "health"]

USER nonroot:nonroot
ENTRYPOINT ["/app/service"]
