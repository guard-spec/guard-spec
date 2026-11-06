# syntax=docker/dockerfile:1
# Control-plane release image used by GoReleaser (.goreleaser.yaml): the static
# binary is built outside and copied in per platform. Not for local builds; see
# the other Dockerfiles in this directory. The gateway release image needs cgo
# (-tags onnx) and is built from build/gateway.Dockerfile instead.

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

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
