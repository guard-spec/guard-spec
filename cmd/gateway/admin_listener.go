// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/guard-spec/guard-spec/internal/tlsreload"
	"github.com/guard-spec/guard-spec/internal/version"
)

// The internal admin listener (RF-da721d14). With ADMIN_LISTEN_ADDR the
// gateway serves /health, /readyz and the /admin routes on a second port
// over mutual TLS:
//
//	ADMIN_TLS_CERT_FILE, ADMIN_TLS_KEY_FILE  its certificate
//	ADMIN_TLS_CLIENT_CA_FILE                 the CA whose certificates may call it
//
// A caller without a certificate of that CA is refused in the handshake. The
// files are read again when they change (short-lived certificates). The
// /admin routes then leave the public listener; they still need
// GATEWAY_ADMIN_TOKEN when it is set, and with mutual TLS they work without
// it. The control plane reads /readyz here (GATEWAY_URL=https://...:8443 with
// GATEWAY_TLS_*).

// adminListenerConfig is ADMIN_LISTEN_ADDR and the ADMIN_TLS_* files.
type adminListenerConfig struct {
	addr  string
	files tlsreload.Files
}

func loadAdminListenerConfig(get func(string) string) (adminListenerConfig, error) {
	c := adminListenerConfig{addr: strings.TrimSpace(get("ADMIN_LISTEN_ADDR")), files: tlsreload.Files{
		Cert: strings.TrimSpace(get("ADMIN_TLS_CERT_FILE")), Key: strings.TrimSpace(get("ADMIN_TLS_KEY_FILE")),
		CA: strings.TrimSpace(get("ADMIN_TLS_CLIENT_CA_FILE"))}}
	if c.addr == "" {
		if c.files.Cert != "" || c.files.Key != "" || c.files.CA != "" {
			return c, errors.New("ADMIN_TLS_* is set without ADMIN_LISTEN_ADDR")
		}
		return c, nil
	}
	if c.files.Cert == "" || c.files.Key == "" || c.files.CA == "" {
		return c, errors.New("ADMIN_LISTEN_ADDR needs ADMIN_TLS_CERT_FILE, ADMIN_TLS_KEY_FILE and ADMIN_TLS_CLIENT_CA_FILE (mutual TLS)")
	}
	return c, nil
}

// registerProbes mounts /health and /readyz, which need no authentication.
func registerProbes(app *fiber.App, gw gateway) {
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "version": version.String()})
	})
	// Readiness. Reports which detection layers run, so a release image
	// started without /models shows it runs L1 only. 503 (same body, status
	// "degraded") when a layer the configuration requires is missing; a
	// degraded gateway that does not require its models stays ready.
	app.Get("/readyz", func(c *fiber.Ctx) error {
		det := gw.detector.current()
		status, code := "ready", fiber.StatusOK
		if !det.ready() {
			status, code = "degraded", fiber.StatusServiceUnavailable
		}
		return c.Status(code).JSON(fiber.Map{"status": status, "version": version.String(), "detector": det})
	})
}

// newAdminApp is the app of the admin listener: probes and /admin.
func newAdminApp(gw gateway) *fiber.App {
	app := fiber.New(fiber.Config{ServerHeader: "guard-spec", DisableStartupMessage: true})
	registerProbes(app, gw)
	auth := func(c *fiber.Ctx) error { return c.Next() } // mutual TLS authenticated the caller
	if gw.adminToken != "" {
		auth = adminAuth(gw.adminToken)
	}
	registerAdmin(app, gw, auth)
	return app
}

// serveAdmin starts the admin listener; the returned app is shut down with
// the gateway.
func serveAdmin(cfg adminListenerConfig, gw gateway) (*fiber.App, error) {
	app, _, err := listenAdmin(cfg, gw)
	return app, err
}

// listenAdmin is serveAdmin that also returns the address it listens on.
func listenAdmin(cfg adminListenerConfig, gw gateway) (*fiber.App, string, error) {
	reloader, err := tlsreload.New(cfg.files)
	if err != nil {
		return nil, "", err
	}
	ln, err := tls.Listen("tcp", cfg.addr, reloader.ServerConfig())
	if err != nil {
		return nil, "", err
	}
	app := newAdminApp(gw)
	go func() {
		slog.Info("admin listener (mutual TLS)", "addr", cfg.addr)
		if err := app.Listener(ln); err != nil {
			slog.Error("admin listener", "err", err)
		}
	}()
	return app, ln.Addr().String(), nil
}
