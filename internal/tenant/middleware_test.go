// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package tenant

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/clientip"
)

// A key limited to addresses works only from them; the address is the one
// resolved through the trusted proxies, so a client cannot send its own
// X-Forwarded-For. Unknown or expired keys (the lookup's error) stay 401.
// Served on a real loopback socket: fiber's Test has no peer address.
func TestMiddlewareAllowedAddresses(t *testing.T) {
	org := uuid.New()
	open, local, remote := HashKey("open"), HashKey("local"), HashKey("remote")
	lookup := func(_ context.Context, hash string) (KeyInfo, error) {
		switch hash {
		case open:
			return KeyInfo{OrgID: org}, nil
		case local:
			return KeyInfo{OrgID: org, AllowedCIDRs: ParseCIDRs([]string{"127.0.0.1", "::1", "garbage"})}, nil
		case remote:
			return KeyInfo{OrgID: org, AllowedCIDRs: ParseCIDRs([]string{"203.0.113.0/24"})}, nil
		}
		return KeyInfo{}, errors.New("unknown key")
	}
	proxies, err := clientip.ParseTrustedProxies("127.0.0.0/8, ::1")
	if err != nil {
		t.Fatal(err)
	}
	serve := func(t *testing.T, trusted bool) string {
		t.Helper()
		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		if trusted {
			app.Use(clientip.Middleware(proxies))
		}
		app.Use(Middleware(lookup))
		app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(200) })
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = app.Listener(ln) }()
		t.Cleanup(func() { _ = app.Shutdown() })
		return "http://" + ln.Addr().String() + "/"
	}
	tests := []struct {
		name    string
		key     string
		trusted bool
		xff     string
		want    int
	}{
		{"open key from anywhere", "open", false, "", 200},
		{"unknown key", "nope", false, "", 401},
		{"key limited to the caller's address", "local", false, "", 200},
		{"key limited to another network", "remote", false, "", 403},
		{"header without trusted proxies is ignored", "remote", false, "203.0.113.5", 403},
		{"trusted proxy forwards an allowed client", "remote", true, "203.0.113.5", 200},
		{"trusted proxy forwards another client", "remote", true, "198.51.100.7", 403},
		{"client cannot spoof through the proxy", "remote", true, "203.0.113.5, 198.51.100.7", 403},
		{"through the proxy the loopback key no longer matches", "local", true, "203.0.113.5", 403},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url := serve(t, tc.trusted)
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("x-api-key", tc.key)
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestParseCIDRs(t *testing.T) {
	nets := ParseCIDRs([]string{" 10.0.0.0/8 ", "192.0.2.1", "::1", "", "not-a-cidr", "300.1.1.1"})
	if len(nets) != 3 {
		t.Fatalf("parsed %d networks, want 3: %v", len(nets), nets)
	}
	if ones, bits := nets[1].Mask.Size(); ones != 32 || bits != 32 {
		t.Errorf("single IPv4 address mask = %d/%d", ones, bits)
	}
	if ones, bits := nets[2].Mask.Size(); ones != 128 || bits != 128 {
		t.Errorf("single IPv6 address mask = %d/%d", ones, bits)
	}
}
