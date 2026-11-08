// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
)

// Hot reload of the models (ml.Live.Reload) has two triggers:
//
//   - SIGHUP reloads the current targets from disk: the configured (or last
//     chosen) classifier and shadow candidate, or the manifest's recommended
//     classifier when no version is pinned. Its outcome goes to the log and to
//     /readyz (detector.models.reload).
//   - POST /admin/models/reload, with "Authorization: Bearer
//     $GATEWAY_ADMIN_TOKEN", reloads and can switch targets (body:
//     ml.ReloadRequest). It answers when the swap is done, or 409 with the
//     error when nothing changed. GET /admin/models returns the status. Both
//     are off (404) unless GATEWAY_ADMIN_TOKEN is set.
//
// A reload verifies every file against the manifest's SHA-256 and loads the
// model fully before swapping; on any failure the running models stay.

// reloadTimeout bounds one reload triggered by SIGHUP.
const reloadTimeout = 5 * time.Minute

// watchReload reloads on every SIGHUP until ctx is done.
func watchReload(ctx context.Context, live *ml.Live) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				slog.Info("SIGHUP: reloading models")
				rctx, cancel := context.WithTimeout(ctx, reloadTimeout)
				_, _ = live.Reload(rctx, ml.ReloadRequest{}) // logged and reported by Status
				cancel()
			}
		}
	}()
}

// adminAuth checks the bearer token in constant time; with no token
// configured the admin routes do not exist.
func adminAuth(token string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if token == "" {
			return fiber.ErrNotFound
		}
		got, ok := strings.CutPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			return c.Status(fiber.StatusUnauthorized).JSON(errorBody("invalid admin token", "invalid_request_error", "unauthorized"))
		}
		return c.Next()
	}
}

// registerAdmin mounts the model admin routes.
func registerAdmin(app *fiber.App, gw gateway, auth fiber.Handler) {
	admin := app.Group("/admin", auth)
	admin.Get("/models", func(c *fiber.Ctx) error {
		if gw.live == nil {
			return c.Status(fiber.StatusNotFound).JSON(errorBody("no model layers", "invalid_request_error", "not_found"))
		}
		return c.JSON(gw.live.Status())
	})
	admin.Post("/models/reload", func(c *fiber.Ctx) error {
		if gw.live == nil {
			return c.Status(fiber.StatusNotFound).JSON(errorBody("no model layers", "invalid_request_error", "not_found"))
		}
		var req ml.ReloadRequest
		if len(c.Body()) > 0 {
			if err := c.BodyParser(&req); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(errorBody("invalid body", "invalid_request_error", "invalid_body"))
			}
		}
		ctx, cancel := context.WithTimeout(gw.base, reloadTimeout)
		defer cancel()
		res, err := gw.live.Reload(ctx, req)
		if errors.Is(err, ml.ErrReload) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error":  fiber.Map{"message": err.Error(), "type": "server_error", "code": "reload_failed"},
				"models": gw.live.Status()})
		}
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(errorBody(err.Error(), "server_error", "reload_failed"))
		}
		return c.JSON(fiber.Map{"reloaded": res, "models": gw.live.Status()})
	})
}
