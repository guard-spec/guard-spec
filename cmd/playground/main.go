// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Command playground is the public playground's backend: a small proxy in
// front of a Guard Spec gateway that serves one route, POST /v1/scan, to the
// playground page of the website.
//
// It holds the gateway's API key, so no key reaches the browser; it only
// calls the gateway's scan endpoints (never an LLM); and it limits what a
// visitor can do: allowed origins only (CORS), a token bucket per client IP
// (per minute and per day), a global budget, a bound on concurrent scans,
// small inputs and bodies, timeouts, and an optional Cloudflare Turnstile
// check. It stores nothing and logs no request content and no client
// addresses: only counters. See deploy/playground/README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guard-spec/guard-spec/internal/version"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "health": // the image's HEALTHCHECK (distroless: no curl)
			os.Exit(healthCheck())
		case "--version", "version":
			fmt.Println(version.String())
			return
		}
	}

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	if len(cfg.AllowedOrigins) == 0 && !cfg.AllowNoOrigin {
		slog.Warn("no ALLOWED_ORIGINS and ALLOW_NO_ORIGIN=false: every scan is refused")
	}
	srv := newServer(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go srv.run(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cfg.GatewayTimeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		slog.Info("playground listening", "addr", cfg.Addr, "version", version.String(),
			"origins", len(cfg.AllowedOrigins), "per_minute", cfg.PerMinute, "per_day", cfg.PerDay,
			"max_input_bytes", cfg.MaxInput, "turnstile", cfg.TurnstileSecret != "")
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdown)
	srv.logStats()
}

// healthCheck calls /healthz of the local server.
func healthCheck() int {
	addr := os.Getenv("PLAYGROUND_ADDR")
	if addr == "" {
		addr = ":8090"
	}
	if addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
