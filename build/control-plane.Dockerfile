# syntax=docker/dockerfile:1
# Control plane: Go management API (no ORT, no CGO needed) and the admin UI.

# --- admin UI (web/) ---
# Built when web/package.json exists; otherwise web/dist keeps the committed
# placeholder page, so the image builds before the UI does.
FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da AS web

WORKDIR /web
COPY web/ ./
RUN if [ -f package.json ]; then npm ci --no-audit --no-fund && npm run build; fi

# --- Go build ---
FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# The UI is embedded from web/dist (go:embed).
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w" \
    -o /out/control-plane ./cmd/control-plane/ \
 && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/doctor ./cmd/doctor/

# --- runtime image ---
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

WORKDIR /app
COPY --from=builder /out/control-plane /out/doctor ./
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/LICENSE /src/NOTICE /src/THIRD_PARTY_LICENSES.md /usr/share/doc/guard-spec/

EXPOSE 8081 9091
HEALTHCHECK --interval=10s --timeout=3s CMD ["/app/control-plane", "health"]

ENTRYPOINT ["/app/control-plane"]
