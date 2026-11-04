// Package auth handles control plane logins, sessions and per-organization roles.
package auth

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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

// Roles lists the roles from lowest to highest.
var Roles = []Role{RoleViewer, RoleMember, RoleAdmin, RoleOwner}

const (
	// TokenLifetime is the longest a session lasts; an org's security policy
	// can shorten it for that org's endpoints.
	TokenLifetime = 12 * time.Hour
	// MFATokenLifetime bounds the second step of a login.
	MFATokenLifetime = 5 * time.Minute

	audSession = "session"
	audMFA     = "mfa"
)

// Login methods, stored in sessions.method. An OIDC provider's is
// "oidc:<provider id>".
const (
	MethodPassword = "password"
	MethodGoogle   = "google"
)

// IsSSOMethod reports whether a login method is an SSO one.
func IsSSOMethod(m string) bool { return m == MethodGoogle || strings.HasPrefix(m, "oidc:") }

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

// claims are the JWT claims of both token kinds: a session token (aud
// "session", sid set) and an mfa_token (aud "mfa", jti is the challenge).
type claims struct {
	jwt.RegisteredClaims
	SID     string `json:"sid,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

func sign(secret []byte, c claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret)
}

func parse(secret []byte, raw, aud string) (claims, error) {
	var c claims
	_, err := jwt.ParseWithClaims(raw, &c, func(*jwt.Token) (any, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithAudience(aud))
	return c, err
}

// IssueSessionToken signs the token of session sid, valid until expires.
func IssueSessionToken(secret []byte, userID, sid uuid.UUID, expires time.Time) (string, error) {
	now := time.Now()
	return sign(secret, claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audSession},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
		SID: sid.String(),
	})
}

// ParseSessionToken validates a session token and returns its user and
// session. Tokens without a session id (issued before sessions existed) and
// mfa_tokens are refused.
func ParseSessionToken(secret []byte, raw string) (userID, sid uuid.UUID, err error) {
	c, err := parse(secret, raw, audSession)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if userID, err = uuid.Parse(c.Subject); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if sid, err = uuid.Parse(c.SID); err != nil {
		return uuid.Nil, uuid.Nil, errors.New("token has no session")
	}
	return userID, sid, nil
}

// MFA token purposes: verify asks for a code, enroll for a 2FA setup.
const (
	PurposeVerify = "verify"
	PurposeEnroll = "enroll"
)

// IssueMFAToken signs the mfa_token of challenge jti (5 minutes).
func IssueMFAToken(secret []byte, userID, jti uuid.UUID, purpose string) (string, error) {
	now := time.Now()
	return sign(secret, claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audMFA},
			ID:        jti.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(MFATokenLifetime)),
		},
		Purpose: purpose,
	})
}

// ParseMFAToken validates an mfa_token. Single use is enforced by the
// challenge row, not here.
func ParseMFAToken(secret []byte, raw string) (userID, jti uuid.UUID, purpose string, err error) {
	c, err := parse(secret, raw, audMFA)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	if userID, err = uuid.Parse(c.Subject); err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	if jti, err = uuid.Parse(c.ID); err != nil {
		return uuid.Nil, uuid.Nil, "", errors.New("mfa token has no id")
	}
	if c.Purpose != PurposeVerify && c.Purpose != PurposeEnroll {
		return uuid.Nil, uuid.Nil, "", errors.New("mfa token has no purpose")
	}
	return userID, jti, c.Purpose, nil
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

// CurrentSession returns the session checked by Required; ok is false for a
// request authenticated otherwise (an mfa_token while enrolling).
func CurrentSession(c *fiber.Ctx) (Session, bool) {
	s, ok := c.Locals("session").(Session)
	return s, ok
}

// BearerToken returns the bearer token of a request, or "".
func BearerToken(c *fiber.Ctx) string {
	const prefix = "Bearer "
	header := c.Get("Authorization")
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return ""
	}
	return header[len(prefix):]
}

// Deny writes an error with a machine-readable code next to the message.
func Deny(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{"error": message, "code": code})
}

// Required rejects requests without a valid session token: a bad signature,
// an expired token, or a session that was revoked or whose user is disabled.
func Required(secret []byte, sessions SessionLookup) fiber.Handler {
	return func(c *fiber.Ctx) error {
		raw := BearerToken(c)
		if raw == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "authentication required"})
		}
		userID, sid, err := ParseSessionToken(secret, raw)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		sess, err := sessions.Lookup(c.Context(), sid)
		if errors.Is(err, ErrNoSession) || (err == nil && sess.UserID != userID) {
			return Deny(c, fiber.StatusUnauthorized, "session_revoked", "session expired or revoked")
		}
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
		c.Locals("user_id", userID)
		c.Locals("session", sess)
		return c.Next()
	}
}

// RequireRole checks the caller's role in :orgId and the org's security
// policy (login method, 2FA, session lifetime), and injects org_id into
// c.Locals. Run it after Required.
func RequireRole(db *pgxpool.Pool, min Role) fiber.Handler {
	return func(c *fiber.Ctx) error {
		orgID, err := uuid.Parse(c.Params("orgId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid org id"})
		}
		var (
			role                   Role
			requireMFA, ssoSatisfy bool
			allowedMethods         []string
			lifetimeHours          int
		)
		err = tenant.WithOrg(c.Context(), db, orgID, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(),
				`SELECT m.role::text, COALESCE(s.require_mfa, false), COALESCE(s.sso_satisfies_mfa, false),
				        s.allowed_login_methods, COALESCE(s.session_lifetime_hours, 12)
				 FROM org_memberships m LEFT JOIN org_security s ON s.org_id = m.org_id
				 WHERE m.user_id = $1 AND m.org_id = $2`,
				UserID(c), orgID).Scan(&role, &requireMFA, &ssoSatisfy, &allowedMethods, &lifetimeHours)
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
		if err != nil || !HasRole(role, min) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
		}
		if sess, ok := CurrentSession(c); ok {
			if code, msg := checkOrgSecurity(sess, requireMFA, ssoSatisfy, allowedMethods, lifetimeHours, time.Now()); code != "" {
				status := fiber.StatusForbidden
				if code == "session_expired" {
					status = fiber.StatusUnauthorized
				}
				return Deny(c, status, code, msg)
			}
		}
		c.Locals("org_id", orgID)
		c.Locals("org_role", role)
		return c.Next()
	}
}

// checkOrgSecurity applies an org's security policy to a session. It returns
// an error code and message, or "" when the session may use the org.
func checkOrgSecurity(s Session, requireMFA, ssoSatisfies bool, allowed []string, lifetimeHours int, now time.Time) (string, string) {
	if allowed != nil && !slices.Contains(allowed, s.Method) {
		return "login_method_not_allowed", "this organization does not allow the login method of this session"
	}
	if requireMFA && !s.MFA && !(ssoSatisfies && IsSSOMethod(s.Method)) {
		return "mfa_required", "this organization requires two-factor authentication; log in again with 2FA"
	}
	if lifetimeHours > 0 && now.Sub(s.CreatedAt) > time.Duration(lifetimeHours)*time.Hour {
		return "session_expired", "this organization's session lifetime has passed; log in again"
	}
	return "", ""
}

// CallerRole returns the caller's role in the org checked by RequireRole.
func CallerRole(c *fiber.Ctx) Role {
	v, _ := c.Locals("org_role").(Role)
	return v
}

// ParseRole returns the role named s, or false for an unknown name.
func ParseRole(s string) (Role, bool) {
	r := Role(s)
	return r, roleRank[r] > 0
}
