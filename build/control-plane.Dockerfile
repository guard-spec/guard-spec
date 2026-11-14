# syntax=docker/dockerfile:1
# Control plane: Go management API (no ORT, no CGO needed) and the admin UI.

# --- admin UI (web/) ---
# Built when web/package.json exists; otherwise web/dist keeps the committed
# placeholder page, so the image builds before the UI does.
FROM node:25-bookworm-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS web

WORKDIR /web
COPY web/ ./
RUN if [ -f package.json ]; then npm ci --no-audit --no-fund && npm run build; fi

# --- Go build ---
FROM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS builder

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
# Chainguard static (Wolfi): CA certificates, tzdata and passwd only; no
# shell. Same nonroot user (65532) as distroless/static had.
FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9

WORKDIR /app
COPY --from=builder /out/control-plane /out/doctor ./
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/LICENSE /src/NOTICE /src/THIRD_PARTY_LICENSES.md /usr/share/doc/guard-spec/

EXPOSE 8081 9091
HEALTHCHECK --interval=10s --timeout=3s CMD ["/app/control-plane", "health"]

ENTRYPOINT ["/app/control-plane"]
