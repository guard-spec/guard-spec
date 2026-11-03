# syntax=docker/dockerfile:1
# Release image used by GoReleaser (.goreleaser.yaml): the static binary is built
# outside and copied in per platform. Not for local builds; see the other
# Dockerfiles in this directory.

FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETPLATFORM
ARG BINARY

WORKDIR /app
COPY ${TARGETPLATFORM}/${BINARY} /app/service
COPY migrations /app/migrations

USER nonroot:nonroot
ENTRYPOINT ["/app/service"]
