package tenant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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

// LookupFn resolves an API key hash to org/project IDs.
type LookupFn func(ctx context.Context, keyHash string) (orgID, projectID uuid.UUID, err error)

// Middleware returns a Fiber handler that validates the API key and injects
// org_id / project_id into c.Locals for downstream handlers.
func Middleware(lookup LookupFn) fiber.Handler {
	return func(c *fiber.Ctx) error {
		raw := extractKey(c)
		if raw == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing API key — pass Authorization: Bearer <key> or x-api-key header",
			})
		}

		hash := HashKey(raw)
		orgID, projID, err := lookup(c.Context(), hash)
		if err != nil || orgID == uuid.Nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid API key",
			})
		}

		c.Locals("org_id", orgID)
		c.Locals("project_id", projID)
		return c.Next()
	}
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
