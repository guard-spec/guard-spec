# syntax=docker/dockerfile:1
# Control plane: Go management API (no ORT, no CGO needed)

FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w" \
    -o /out/control-plane ./cmd/control-plane/

# --- runtime image ---
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

WORKDIR /app
COPY --from=builder /out/control-plane .
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/LICENSE /src/NOTICE /src/THIRD_PARTY_LICENSES.md /usr/share/doc/guard-spec/

EXPOSE 8081 9091
HEALTHCHECK --interval=10s --timeout=3s CMD ["/app/control-plane", "health"]

ENTRYPOINT ["/app/control-plane"]
