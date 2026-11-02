// Package auth handles control plane logins and per-organization roles.
package auth

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/tenant"
	"golang.org/x/crypto/bcrypt"
)

// Role is an org_role value.
type Role string

const (
	RoleViewer Role = "viewer"
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
	RoleOwner  Role = "owner"
)

var roleRank = map[Role]int{RoleViewer: 1, RoleMember: 2, RoleAdmin: 3, RoleOwner: 4}

const tokenLifetime = 12 * time.Hour

// dummyHash keeps login timing the same for unknown users.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("unknown-user"), bcrypt.DefaultCost)

// HashPassword returns the bcrypt hash stored in users.hashed_password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// CheckPassword compares a password with a stored hash. An empty hash always fails.
func CheckPassword(hash, password string) bool {
	if hash == "" {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// IssueToken signs a session token for userID.
func IssueToken(secret []byte, userID uuid.UUID) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(tokenLifetime)),
	}).SignedString(secret)
}

// ParseToken validates a session token and returns its user ID.
func ParseToken(secret []byte, raw string) (uuid.UUID, error) {
	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(claims.Subject)
}

// HasRole reports whether role meets min. Unknown roles never do.
func HasRole(role, min Role) bool {
	return roleRank[role] > 0 && roleRank[role] >= roleRank[min]
}

// UserID returns the authenticated user from a fiber context.
func UserID(c *fiber.Ctx) uuid.UUID {
	v, _ := c.Locals("user_id").(uuid.UUID)
	return v
}

// Required rejects requests without a valid bearer token.
func Required(secret []byte) fiber.Handler {
	return func(c *fiber.Ctx) error {
		const prefix = "Bearer "
		header := c.Get("Authorization")
		if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "authentication required"})
		}
		userID, err := ParseToken(secret, header[len(prefix):])
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		c.Locals("user_id", userID)
		return c.Next()
	}
}

// RequireRole checks the caller's role in :orgId and injects org_id into c.Locals.
// Run it after Required.
func RequireRole(db *pgxpool.Pool, min Role) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
		var role Role
		err = tenant.WithOrg(c.Context(), db, orgID, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(),
				`SELECT role::text FROM org_memberships WHERE user_id = $1 AND org_id = $2`,
				UserID(c), orgID).Scan(&role)
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
		if err != nil || !HasRole(role, min) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
		}
		c.Locals("org_id", orgID)
		return c.Next()
	}
}
