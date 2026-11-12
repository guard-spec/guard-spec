package main

import (
	"net"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/clientip"
)

// The client address used by rate limits, sessions and the activity log:
// internal/clientip, shared with the gateway (TRUSTED_PROXIES).

// parseTrustedProxies parses TRUSTED_PROXIES: comma-separated CIDRs or IPs.
func parseTrustedProxies(s string) ([]*net.IPNet, error) {
	return clientip.ParseTrustedProxies(s)
}

// resolveClientIP returns the client address of a request from remote with
// the X-Forwarded-For value xff.
func resolveClientIP(nets []*net.IPNet, remote net.IP, xff string) string {
	return clientip.Resolve(nets, remote, xff)
}

// clientIPMiddleware stores the client address for clientIP.
func clientIPMiddleware(nets []*net.IPNet) fiber.Handler {
	return clientip.Middleware(nets)
}

// clientIP is the request's client address (see clientIPMiddleware).
func clientIP(c *fiber.Ctx) string {
	return clientip.FromCtx(c)
}
