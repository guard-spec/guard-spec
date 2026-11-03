# syntax=docker/dockerfile:1
# Release image used by GoReleaser (.goreleaser.yaml): the static binary is built
# outside and copied in per platform. Not for local builds; see the other
# Dockerfiles in this directory.

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETPLATFORM
ARG BINARY

WORKDIR /app
COPY ${TARGETPLATFORM}/${BINARY} /app/service
COPY migrations /app/migrations
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.md /usr/share/doc/guard-spec/

USER nonroot:nonroot
ENTRYPOINT ["/app/service"]
