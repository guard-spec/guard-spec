// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package clientip finds the client address of a request behind reverse
// proxies, for both services.
//
// Behind a reverse proxy every request comes from the proxy, so anything
// keyed by address (rate limits, sessions, the activity log, an API key's
// allowed addresses) would see the proxy. TRUSTED_PROXIES lists the proxies
// (CIDRs or addresses) whose X-Forwarded-For is believed. The header is read
// from the right: the first address that is not a trusted proxy is the
// client, so a client cannot choose its address by sending the header
// itself. Without TRUSTED_PROXIES the header is ignored and the TCP peer is
// the client.
package clientip

import (
	"fmt"
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// ParseTrustedProxies parses TRUSTED_PROXIES: comma-separated CIDRs or IPs.
func ParseTrustedProxies(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES: %q is not an IP address or CIDR", item)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			item = fmt.Sprintf("%s/%d", ip, bits)
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q is not an IP address or CIDR", item)
		}
		out = append(out, n)
	}
	return out, nil
}

// Contains reports whether ip is in one of nets.
func Contains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolve returns the client address of a request from remote with the
// X-Forwarded-For value xff, given the trusted proxies.
func Resolve(nets []*net.IPNet, remote net.IP, xff string) string {
	if len(nets) == 0 || remote == nil || !Contains(nets, remote) || xff == "" {
		return remote.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			break // a malformed hop: stop at the last address we can vouch for
		}
		if !Contains(nets, ip) {
			return ip.String()
		}
		remote = ip
	}
	return remote.String()
}

// localsKey is where Middleware keeps the address.
const localsKey = "client_ip"

// Middleware stores the client address for FromCtx.
func Middleware(nets []*net.IPNet) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Locals(localsKey, Resolve(nets, c.Context().RemoteIP(), c.Get(fiber.HeaderXForwardedFor)))
		return c.Next()
	}
}

// FromCtx is the request's client address: what Middleware resolved, or the
// TCP peer before it ran.
func FromCtx(c *fiber.Ctx) string {
	if ip, ok := c.Locals(localsKey).(string); ok {
		return ip
	}
	return c.IP()
}
