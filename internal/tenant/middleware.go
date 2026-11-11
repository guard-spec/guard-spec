package tenant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/clientip"
)

type contextKey int

const (
	keyOrgID contextKey = iota
	keyProjectID
)

// OrgID returns the authenticated org ID from a fiber context.
func OrgID(c *fiber.Ctx) (uuid.UUID, error) {
	v, ok := c.Locals("org_id").(uuid.UUID)
	if !ok || v == uuid.Nil {
		return uuid.Nil, errors.New("no org_id in context")
	}
	return v, nil
}

// ProjectID returns the project ID from a fiber context (may be Nil).
func ProjectID(c *fiber.Ctx) uuid.UUID {
	v, _ := c.Locals("project_id").(uuid.UUID)
	return v
}

// KeyInfo is what the gateway knows about a live API key: its scope and,
// when the key is restricted to addresses (migration 028), the networks a
// caller must come from.
type KeyInfo struct {
	OrgID     uuid.UUID
	ProjectID uuid.UUID // Nil: an org-wide key
	// AllowedCIDRs is empty for a key any address may use.
	AllowedCIDRs []*net.IPNet
}

// LookupFn resolves an API key hash to the key, or an error for a key that
// is unknown, revoked or expired.
type LookupFn func(ctx context.Context, keyHash string) (KeyInfo, error)

// ParseCIDRs parses the stored allowed_cidrs of a key (CIDRs or single
// addresses). A value that does not parse is skipped: the key was validated
// when it was saved, and a stray value must not open the key to everyone.
func ParseCIDRs(items []string) []*net.IPNet {
	var out []*net.IPNet
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") {
			ip := net.ParseIP(item)
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if _, n, err := net.ParseCIDR(item); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// Middleware returns a Fiber handler that validates the API key and injects
// org_id / project_id into c.Locals for downstream handlers. A key with
// allowed addresses is refused (403) from any other address; the address
// is the one clientip.Middleware resolved (TRUSTED_PROXIES), never a
// header a client sent on its own.
func Middleware(lookup LookupFn) fiber.Handler {
	return func(c *fiber.Ctx) error {
		raw := extractKey(c)
		if raw == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing API key — pass Authorization: Bearer <key> or x-api-key header",
			})
		}

		hash := HashKey(raw)
		key, err := lookup(c.Context(), hash)
		if err != nil || key.OrgID == uuid.Nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid API key",
			})
		}
		if len(key.AllowedCIDRs) > 0 {
			addr := clientip.FromCtx(c)
			ip := net.ParseIP(addr)
			if ip == nil || !clientip.Contains(key.AllowedCIDRs, ip) {
				slog.Info("API key refused: address not allowed", "org", key.OrgID, "ip", addr)
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "API key is not allowed from this address",
				})
			}
		}

		c.Locals("org_id", key.OrgID)
		c.Locals("project_id", key.ProjectID)
		c.Locals("api_key_hash", hash)
		return c.Next()
	}
}

// KeyHash returns the hash of the request's API key, or "" before Middleware.
func KeyHash(c *fiber.Ctx) string {
	v, _ := c.Locals("api_key_hash").(string)
	return v
}

func extractKey(c *fiber.Ctx) string {
	auth := c.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return c.Get("x-api-key")
}

// HashKey returns the SHA-256 hex digest used as the api_keys table PK.
func HashKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
