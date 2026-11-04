package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// The client address used by rate limits, sessions and the activity log.
//
// Behind a reverse proxy every request comes from the proxy, so limits keyed
// by address would be shared by everyone. TRUSTED_PROXIES lists the proxies
// (CIDRs or addresses) whose X-Forwarded-For is believed. The header is read
// from the right: the first address that is not a trusted proxy is the
// client, so a client cannot choose its address by sending the header itself.
// Without TRUSTED_PROXIES the header is ignored.

// parseTrustedProxies parses TRUSTED_PROXIES: comma-separated CIDRs or IPs.
func parseTrustedProxies(s string) ([]*net.IPNet, error) {
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

func trusted(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveClientIP returns the client address of a request from remote with
// the X-Forwarded-For value xff.
func resolveClientIP(nets []*net.IPNet, remote net.IP, xff string) string {
	if len(nets) == 0 || remote == nil || !trusted(nets, remote) || xff == "" {
		return remote.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			break // a malformed hop: stop at the last address we can vouch for
		}
		if !trusted(nets, ip) {
			return ip.String()
		}
		remote = ip
	}
	return remote.String()
}

// clientIPMiddleware stores the client address for clientIP.
func clientIPMiddleware(nets []*net.IPNet) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Locals("client_ip", resolveClientIP(nets, c.Context().RemoteIP(), c.Get(fiber.HeaderXForwardedFor)))
		return c.Next()
	}
}

// clientIP is the request's client address (see clientIPMiddleware).
func clientIP(c *fiber.Ctx) string {
	if ip, ok := c.Locals("client_ip").(string); ok {
		return ip
	}
	return c.IP()
}
