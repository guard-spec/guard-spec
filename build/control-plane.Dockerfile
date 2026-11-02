# syntax=docker/dockerfile:1
# Control plane: Go management API (no ORT, no CGO needed)

FROM golang:1.22-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w" \
    -o /out/control-plane ./cmd/control-plane/

# --- runtime image ---
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=builder /out/control-plane .
COPY --from=builder /src/migrations ./migrations

EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=3s CMD ["/app/control-plane", "health"]

ENTRYPOINT ["/app/control-plane"]
