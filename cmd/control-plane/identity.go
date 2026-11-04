package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// Logins, sessions and two-factor authentication (migration 013).
//
// A login (password, or SSO through /auth/oidc/exchange) ends in one of:
//   - a session: {"token", "user"};
//   - {"mfa_required": true, "mfa_token", "methods"} when the user has 2FA:
//     POST /auth/mfa/verify with a TOTP or recovery code finishes it;
//   - {"mfa_enroll_required": true, "mfa_token"} when an organization of the
//     user requires 2FA and the user has none: the mfa_token is then the
//     bearer token of /auth/mfa/totp/setup and /confirm, and nothing else.
//
// An mfa_token is a 5-minute JWT (aud "mfa") naming a row of mfa_challenges,
// which allows 5 attempts and one success.

const (
	maxMFAAttempts    = 5
	recoveryCodeCount = 10
	totpIssuer        = "Guard Spec"
)

// identity holds what the login, session and SSO handlers share.
type identity struct {
	db       *pgxpool.Pool
	secret   []byte
	sessions *auth.Sessions
	lookup   auth.SessionLookup
	box      *auth.SecretBox // nil when MFA_ENC_KEY is not set
	// publicURL is PUBLIC_BASE_URL, the origin SSO callbacks are sent to.
	publicURL string
	client    *http.Client // for OIDC discovery and token calls
	now       func() time.Time

	oidcMu    sync.Mutex
	providers map[uuid.UUID]*oidcProvider
}

func newIdentity(db *pgxpool.Pool, secret []byte, s *appSettings) *identity {
	id := &identity{db: db, secret: secret, sessions: auth.NewSessions(db), box: s.mfaBox,
		publicURL: strings.TrimRight(s.publicURL, "/"), client: s.oidcClient, now: time.Now,
		providers: map[uuid.UUID]*oidcProvider{}}
	id.lookup = id.sessions
	if s.sessionLookup != nil {
		id.lookup = s.sessionLookup
	}
	if id.client == nil {
		id.client = &http.Client{Timeout: 10 * time.Second}
	}
	return id
}

// ── Users ────────────────────────────────────────────────────────────────────

type linkedIdentity struct {
	ProviderID  uuid.UUID `json:"provider_id"`
	Provider    string    `json:"provider"` // google or oidc
	DisplayName string    `json:"display_name"`
	Email       *string   `json:"email"`
}

type meUser struct {
	ID              uuid.UUID        `json:"id"`
	Email           string           `json:"email"`
	DisplayName     *string          `json:"display_name"`
	MFAEnabled      bool             `json:"mfa_enabled"`
	HasPassword     bool             `json:"has_password"`
	Identities      []linkedIdentity `json:"identities"`
	IsInstanceAdmin bool             `json:"is_instance_admin"`
}

func loadMe(ctx context.Context, db *pgxpool.Pool, user uuid.UUID) (meUser, error) {
	me := meUser{Identities: []linkedIdentity{}}
	err := db.QueryRow(ctx,
		`SELECT u.id, u.email, u.display_name, u.hashed_password IS NOT NULL, u.is_instance_admin,
		        EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enabled_at IS NOT NULL)
		 FROM users u WHERE u.id = $1`, user).
		Scan(&me.ID, &me.Email, &me.DisplayName, &me.HasPassword, &me.IsInstanceAdmin, &me.MFAEnabled)
	if err != nil {
		return me, err
	}
	rows, err := db.Query(ctx,
		`SELECT p.id, p.type, p.display_name, i.email FROM user_identities i
		 JOIN identity_providers p ON p.id = i.provider_id WHERE i.user_id = $1 ORDER BY i.created_at`, user)
	if err != nil {
		return me, err
	}
	defer rows.Close()
	for rows.Next() {
		var li linkedIdentity
		if err := rows.Scan(&li.ProviderID, &li.Provider, &li.DisplayName, &li.Email); err != nil {
			return me, err
		}
		me.Identities = append(me.Identities, li)
	}
	return me, rows.Err()
}

func (id *identity) me(c *fiber.Ctx) error {
	me, err := loadMe(c.Context(), id.db, auth.UserID(c))
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(me)
}

// ── Login ────────────────────────────────────────────────────────────────────

func (id *identity) login(c *fiber.Ctx) error {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	var userID uuid.UUID
	var hash *string
	var disabled *time.Time
	err := id.db.QueryRow(c.Context(),
		`SELECT id, hashed_password, disabled_at FROM users WHERE email = $1`, req.Email).Scan(&userID, &hash, &disabled)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return serverError(c, err)
	}
	stored := ""
	if hash != nil {
		stored = *hash
	}
	if !auth.CheckPassword(stored, req.Password) {
		// Written after the answer: a known user's row goes to each of their
		// orgs, and the time that takes must not tell which emails exist.
		ip, email := strings.Clone(c.IP()), strings.Clone(truncateRunes(req.Email, 254))
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			logUserEvent(ctx, id.db, userID, "login.failed", ip, map[string]any{"method": auth.MethodPassword, "email": email})
		}()
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	if disabled != nil {
		logUserEvent(c.Context(), id.db, userID, "login.failed", c.IP(),
			map[string]any{"method": auth.MethodPassword, "reason": "disabled"})
		return auth.Deny(c, fiber.StatusForbidden, "account_disabled", "this account is disabled")
	}
	return id.completeLogin(c, userID, auth.MethodPassword, nil)
}

// completeLogin answers a login whose first factor passed: a session, or the
// 2FA step. extra is merged into the answer.
func (id *identity) completeLogin(c *fiber.Ctx, user uuid.UUID, method string, extra fiber.Map) error {
	ctx := c.Context()
	var mfaEnabled bool
	if err := id.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_mfa WHERE user_id = $1 AND enabled_at IS NOT NULL)`, user).
		Scan(&mfaEnabled); err != nil {
		return serverError(c, err)
	}
	merge := func(m fiber.Map) fiber.Map {
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	if mfaEnabled {
		token, err := id.newChallenge(ctx, user, auth.PurposeVerify, method)
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(merge(fiber.Map{"mfa_required": true, "mfa_token": token, "methods": []string{"totp", "recovery"}}))
	}
	required, err := orgsRequireMFA(ctx, id.db, user, method)
	if err != nil {
		return serverError(c, err)
	}
	if required {
		if id.box == nil {
			slog.Error("an organization requires 2FA but MFA_ENC_KEY is not set; 2FA enrollment is impossible")
			return auth.Deny(c, fiber.StatusServiceUnavailable, "mfa_unavailable",
				"two-factor authentication is required but not configured on this server (MFA_ENC_KEY)")
		}
		token, err := id.newChallenge(ctx, user, auth.PurposeEnroll, method)
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(merge(fiber.Map{"mfa_enroll_required": true, "mfa_token": token}))
	}
	out, err := id.startSession(c, user, method, false)
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(merge(out))
}

// orgsRequireMFA reports whether an organization of user requires 2FA for a
// login by method (an SSO login passes where the org lets SSO satisfy it).
func orgsRequireMFA(ctx context.Context, db *pgxpool.Pool, user uuid.UUID, method string) (bool, error) {
	var required bool
	err := db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_org_security($1) WHERE require_mfa AND NOT (sso_satisfies_mfa AND $2))`,
		user, auth.IsSSOMethod(method)).Scan(&required)
	return required, err
}

// anyOrgRequiresMFA reports whether an organization of user requires 2FA at all.
func anyOrgRequiresMFA(ctx context.Context, db *pgxpool.Pool, user uuid.UUID) (bool, error) {
	var required bool
	err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_org_security($1) WHERE require_mfa)`, user).Scan(&required)
	return required, err
}

// startSession creates a session and returns {"token", "user"}.
func (id *identity) startSession(c *fiber.Ctx, user uuid.UUID, method string, mfa bool) (fiber.Map, error) {
	sess, err := id.sessions.Create(c.Context(), auth.NewSession{UserID: user, Method: method, MFA: mfa,
		UserAgent: c.Get(fiber.HeaderUserAgent), IP: c.IP()})
	if err != nil {
		return nil, err
	}
	token, err := auth.IssueSessionToken(id.secret, user, sess.ID, sess.ExpiresAt)
	if err != nil {
		return nil, err
	}
	me, err := loadMe(c.Context(), id.db, user)
	if err != nil {
		return nil, err
	}
	logUserEvent(c.Context(), id.db, user, "login.succeeded", c.IP(), map[string]any{"method": method, "mfa": mfa})
	return fiber.Map{"token": token, "user": me}, nil
}

func (id *identity) newChallenge(ctx context.Context, user uuid.UUID, purpose, method string) (string, error) {
	jti := uuid.New()
	if _, err := id.db.Exec(ctx,
		`INSERT INTO mfa_challenges (id, user_id, purpose, method, expires_at) VALUES ($1, $2, $3, $4, NOW() + $5::interval)`,
		jti, user, purpose, method, auth.MFATokenLifetime); err != nil {
		return "", err
	}
	// Expired challenges are not needed for anything; drop them now and then.
	_, _ = id.db.Exec(ctx, `DELETE FROM mfa_challenges WHERE expires_at < NOW() - interval '1 hour'`)
	return auth.IssueMFAToken(id.secret, user, jti, purpose)
}

var errChallengeInvalid = errors.New("the 2FA step expired, was already used or had too many attempts; log in again")

// countAttempt spends one attempt of a live challenge and returns its method.
func (id *identity) countAttempt(ctx context.Context, jti, user uuid.UUID, purpose string) (string, error) {
	var method string
	err := id.db.QueryRow(ctx,
		`UPDATE mfa_challenges SET attempts = attempts + 1
		 WHERE id = $1 AND user_id = $2 AND purpose = $3 AND used_at IS NULL AND expires_at > NOW() AND attempts < $4
		 RETURNING method`, jti, user, purpose, maxMFAAttempts).Scan(&method)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errChallengeInvalid
	}
	return method, err
}

// finishChallenge marks a challenge used; false if it was used meanwhile.
func (id *identity) finishChallenge(ctx context.Context, jti uuid.UUID) (bool, error) {
	tag, err := id.db.Exec(ctx, `UPDATE mfa_challenges SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, jti)
	return tag.RowsAffected() == 1, err
}

// mfaVerify finishes a login with a TOTP or recovery code.
func (id *identity) mfaVerify(c *fiber.Ctx) error {
	var req struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.MFAToken == "" || req.Code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "mfa_token and code are required"})
	}
	user, jti, purpose, err := auth.ParseMFAToken(id.secret, req.MFAToken)
	if err != nil || purpose != auth.PurposeVerify {
		return auth.Deny(c, fiber.StatusUnauthorized, "mfa_token_invalid", "invalid mfa_token")
	}
	ctx := c.Context()
	method, err := id.countAttempt(ctx, jti, user, auth.PurposeVerify)
	if errors.Is(err, errChallengeInvalid) {
		return auth.Deny(c, fiber.StatusUnauthorized, "mfa_token_invalid", err.Error())
	}
	if err != nil {
		return serverError(c, err)
	}
	how, err := id.checkCode(ctx, user, req.Code)
	if err != nil {
		return serverError(c, err)
	}
	if how == "" {
		logUserEvent(ctx, id.db, user, "login.mfa_failed", c.IP(), map[string]any{"method": method})
		return auth.Deny(c, fiber.StatusUnauthorized, "invalid_code", "invalid or already used code")
	}
	if ok, err := id.finishChallenge(ctx, jti); err != nil {
		return serverError(c, err)
	} else if !ok {
		return auth.Deny(c, fiber.StatusUnauthorized, "mfa_token_invalid", errChallengeInvalid.Error())
	}
	if how == "recovery" {
		logUserEvent(ctx, id.db, user, "mfa.recovery_code_used", c.IP(), nil)
	}
	out, err := id.startSession(c, user, method, true)
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(out)
}

// checkCode checks a TOTP code (6 digits) or a recovery code of an enabled
// 2FA. It returns "totp", "recovery" or "" (refused). A TOTP code is refused
// for the step it was used in and every earlier one; a recovery code once.
func (id *identity) checkCode(ctx context.Context, user uuid.UUID, code string) (string, error) {
	code = strings.TrimSpace(code)
	if isDigits(code) && len(code) == 6 {
		if id.box == nil {
			return "", nil
		}
		var sealed []byte
		err := id.db.QueryRow(ctx, `SELECT totp_secret_enc FROM user_mfa WHERE user_id = $1 AND enabled_at IS NOT NULL`, user).
			Scan(&sealed)
		if errors.Is(err, pgx.ErrNoRows) || sealed == nil {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		secret, err := id.box.Open(sealed, user[:])
		if err != nil {
			return "", err
		}
		step, ok := auth.MatchTOTP(string(secret), code, id.now())
		if !ok {
			return "", nil
		}
		tag, err := id.db.Exec(ctx,
			`UPDATE user_mfa SET last_used_step = $2, updated_at = NOW()
			 WHERE user_id = $1 AND (last_used_step IS NULL OR last_used_step < $2)`, user, step)
		if err != nil || tag.RowsAffected() != 1 {
			return "", err // a replay
		}
		return "totp", nil
	}
	norm := normalizeRecoveryCode(code)
	if norm == "" {
		return "", nil
	}
	rows, err := id.db.Query(ctx, `SELECT id, code_hash FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, user)
	if err != nil {
		return "", err
	}
	type rc struct {
		id   uuid.UUID
		hash string
	}
	codes, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (rc, error) {
		var x rc
		return x, r.Scan(&x.id, &x.hash)
	})
	if err != nil {
		return "", err
	}
	for _, x := range codes {
		if bcrypt.CompareHashAndPassword([]byte(x.hash), []byte(norm)) == nil {
			tag, err := id.db.Exec(ctx, `UPDATE mfa_recovery_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, x.id)
			if err != nil || tag.RowsAffected() != 1 {
				return "", err
			}
			return "recovery", nil
		}
	}
	return "", nil
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// recoveryAlphabet has no 0/o, 1/l/i: codes are read and typed by people.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// normalizeRecoveryCode returns "xxxx-xxxx" from what the user typed, or "".
func normalizeRecoveryCode(s string) string {
	s = strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(s))
	if len(s) != 8 {
		return ""
	}
	for _, r := range s {
		if !strings.ContainsRune(recoveryAlphabet, r) {
			return ""
		}
	}
	return s[:4] + "-" + s[4:]
}

// newRecoveryCodes returns fresh codes and their bcrypt hashes.
func newRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, recoveryCodeCount)
	hashes := make([]string, recoveryCodeCount)
	// Bytes at or above limit are skipped, so that every letter is equally likely.
	limit := byte(256 / len(recoveryAlphabet) * len(recoveryAlphabet))
	buf := make([]byte, 1)
	for i := range codes {
		var b strings.Builder
		for n := 0; n < 8; {
			if _, err := rand.Read(buf); err != nil {
				return nil, nil, err
			}
			if buf[0] >= limit {
				continue
			}
			if n == 4 {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryAlphabet[int(buf[0])%len(recoveryAlphabet)])
			n++
		}
		codes[i] = b.String()
		h, err := bcrypt.GenerateFromPassword([]byte(codes[i]), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}
		hashes[i] = string(h)
	}
	return codes, hashes, nil
}

func storeRecoveryCodes(ctx context.Context, tx pgx.Tx, user uuid.UUID, hashes []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, user); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO mfa_recovery_codes (user_id, code_hash) SELECT $1, unnest($2::text[])`, user, hashes)
	return err
}

// ── 2FA self-service ─────────────────────────────────────────────────────────

// sessionOrEnroll authenticates the 2FA setup endpoints: a session token, or
// the mfa_token of an enrollment challenge.
func (id *identity) sessionOrEnroll() fiber.Handler {
	required := auth.Required(id.secret, id.lookup)
	return func(c *fiber.Ctx) error {
		raw := auth.BearerToken(c)
		user, jti, purpose, err := auth.ParseMFAToken(id.secret, raw)
		if err != nil {
			return required(c)
		}
		if purpose != auth.PurposeEnroll {
			return auth.Deny(c, fiber.StatusUnauthorized, "mfa_token_invalid", "this mfa_token cannot enroll 2FA")
		}
		var live bool
		if err := id.db.QueryRow(c.Context(),
			`SELECT EXISTS (SELECT 1 FROM mfa_challenges WHERE id = $1 AND user_id = $2 AND purpose = 'enroll'
			   AND used_at IS NULL AND expires_at > NOW() AND attempts < $3)`, jti, user, maxMFAAttempts).Scan(&live); err != nil {
			return serverError(c, err)
		}
		if !live {
			return auth.Deny(c, fiber.StatusUnauthorized, "mfa_token_invalid", errChallengeInvalid.Error())
		}
		c.Locals("user_id", user)
		c.Locals("mfa_challenge", jti)
		return c.Next()
	}
}

func enrollChallenge(c *fiber.Ctx) (uuid.UUID, bool) {
	v, ok := c.Locals("mfa_challenge").(uuid.UUID)
	return v, ok
}

func (id *identity) noMFAKey(c *fiber.Ctx) error {
	return auth.Deny(c, fiber.StatusServiceUnavailable, "mfa_unavailable",
		"two-factor authentication is not configured on this server: set MFA_ENC_KEY")
}

func (id *identity) totpSetup(c *fiber.Ctx) error {
	if id.box == nil {
		return id.noMFAKey(c)
	}
	user := auth.UserID(c)
	ctx := c.Context()
	var email string
	var enabled bool
	if err := id.db.QueryRow(ctx,
		`SELECT u.email, EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enabled_at IS NOT NULL)
		 FROM users u WHERE u.id = $1`, user).Scan(&email, &enabled); err != nil {
		return serverError(c, err)
	}
	if enabled {
		return auth.Deny(c, fiber.StatusConflict, "mfa_already_enabled", "2FA is already on; turn it off first to set up a new authenticator")
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return serverError(c, err)
	}
	sealed, err := id.box.Seal([]byte(secret), user[:])
	if err != nil {
		return serverError(c, err)
	}
	if _, err := id.db.Exec(ctx,
		`INSERT INTO user_mfa (user_id, pending_secret_enc) VALUES ($1, $2)
		 ON CONFLICT (user_id) DO UPDATE SET pending_secret_enc = EXCLUDED.pending_secret_enc, updated_at = NOW()`,
		user, sealed); err != nil {
		return serverError(c, err)
	}
	return c.JSON(fiber.Map{"secret": secret, "otpauth_url": auth.OTPAuthURL(totpIssuer, email, secret)})
}

func (id *identity) totpConfirm(c *fiber.Ctx) error {
	if id.box == nil {
		return id.noMFAKey(c)
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.Code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "code is required"})
	}
	user := auth.UserID(c)
	ctx := c.Context()
	jti, enrolling := enrollChallenge(c)
	method := ""
	if enrolling {
		var err error
		if method, err = id.countAttempt(ctx, jti, user, auth.PurposeEnroll); errors.Is(err, errChallengeInvalid) {
			return auth.Deny(c, fiber.StatusUnauthorized, "mfa_token_invalid", err.Error())
		} else if err != nil {
			return serverError(c, err)
		}
	}
	var pending []byte
	err := id.db.QueryRow(ctx, `SELECT pending_secret_enc FROM user_mfa WHERE user_id = $1 AND enabled_at IS NULL`, user).
		Scan(&pending)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && pending == nil) {
		return auth.Deny(c, fiber.StatusConflict, "mfa_setup_missing", "start with POST /v1/auth/mfa/totp/setup")
	}
	if err != nil {
		return serverError(c, err)
	}
	secret, err := id.box.Open(pending, user[:])
	if err != nil {
		return serverError(c, err)
	}
	step, ok := auth.MatchTOTP(string(secret), req.Code, id.now())
	if !ok {
		return auth.Deny(c, fiber.StatusUnauthorized, "invalid_code", "invalid code")
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return serverError(c, err)
	}
	err = pgx.BeginFunc(ctx, id.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE user_mfa SET totp_secret_enc = pending_secret_enc, pending_secret_enc = NULL, enabled_at = NOW(),
			   last_used_step = $2, updated_at = NOW()
			 WHERE user_id = $1 AND enabled_at IS NULL AND pending_secret_enc = $3`, user, step, pending)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errChallengeInvalid // confirmed or replaced meanwhile
		}
		return storeRecoveryCodes(ctx, tx, user, hashes)
	})
	if errors.Is(err, errChallengeInvalid) {
		return auth.Deny(c, fiber.StatusConflict, "mfa_setup_missing", "the setup changed meanwhile; start again")
	}
	if err != nil {
		return serverError(c, err)
	}
	logUserEvent(ctx, id.db, user, "mfa.enabled", c.IP(), nil)
	out := fiber.Map{"recovery_codes": codes}
	if enrolling {
		if ok, err := id.finishChallenge(ctx, jti); err != nil {
			return serverError(c, err)
		} else if !ok {
			return auth.Deny(c, fiber.StatusUnauthorized, "mfa_token_invalid", errChallengeInvalid.Error())
		}
		sess, err := id.startSession(c, user, method, true)
		if err != nil {
			return serverError(c, err)
		}
		out["token"], out["user"] = sess["token"], sess["user"]
	}
	return c.JSON(out)
}

func codeBody(c *fiber.Ctx) (string, error) {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return "", errors.New("code is required")
	}
	return req.Code, nil
}

func (id *identity) regenerateRecoveryCodes(c *fiber.Ctx) error {
	code, err := codeBody(c)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	user := auth.UserID(c)
	how, err := id.checkCode(c.Context(), user, code)
	if err != nil {
		return serverError(c, err)
	}
	if how == "" {
		return auth.Deny(c, fiber.StatusUnauthorized, "invalid_code", "invalid or already used code")
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return serverError(c, err)
	}
	if err := pgx.BeginFunc(c.Context(), id.db, func(tx pgx.Tx) error {
		return storeRecoveryCodes(c.Context(), tx, user, hashes)
	}); err != nil {
		return serverError(c, err)
	}
	logUserEvent(c.Context(), id.db, user, "mfa.recovery_codes_regenerated", c.IP(), nil)
	return c.JSON(fiber.Map{"recovery_codes": codes})
}

func (id *identity) disableMFA(c *fiber.Ctx) error {
	code, err := codeBody(c)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	user := auth.UserID(c)
	ctx := c.Context()
	if required, err := anyOrgRequiresMFA(ctx, id.db, user); err != nil {
		return serverError(c, err)
	} else if required {
		return auth.Deny(c, fiber.StatusConflict, "mfa_required_by_org", "an organization you belong to requires 2FA")
	}
	how, err := id.checkCode(ctx, user, code)
	if err != nil {
		return serverError(c, err)
	}
	if how == "" {
		return auth.Deny(c, fiber.StatusUnauthorized, "invalid_code", "invalid or already used code")
	}
	if err := clearMFA(ctx, id.db, user); err != nil {
		return serverError(c, err)
	}
	logUserEvent(ctx, id.db, user, "mfa.disabled", c.IP(), nil)
	return c.Status(204).Send(nil)
}

func clearMFA(ctx context.Context, db *pgxpool.Pool, user uuid.UUID) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM user_mfa WHERE user_id = $1`, user); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, user)
		return err
	})
}

// ── Sessions and password ────────────────────────────────────────────────────

func (id *identity) listSessions(c *fiber.Ctx) error {
	cur, _ := auth.CurrentSession(c)
	rows, err := id.db.Query(c.Context(),
		`SELECT id, created_at, last_seen_at, COALESCE(user_agent, ''), COALESCE(ip, '') FROM sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW() ORDER BY created_at DESC LIMIT 200`,
		auth.UserID(c))
	if err != nil {
		return serverError(c, err)
	}
	type row struct {
		ID         uuid.UUID `json:"id"`
		CreatedAt  time.Time `json:"created_at"`
		LastSeenAt time.Time `json:"last_seen_at"`
		UserAgent  string    `json:"user_agent"`
		IP         string    `json:"ip"`
		Current    bool      `json:"current"`
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.ID, &x.CreatedAt, &x.LastSeenAt, &x.UserAgent, &x.IP)
		x.Current = x.ID == cur.ID
		return x, err
	})
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(fiber.Map{"items": list, "next_cursor": nil, "total": len(list)})
}

func (id *identity) revokeSession(c *fiber.Ctx) error {
	sid, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid session id"})
	}
	ok, err := id.sessions.Revoke(c.Context(), auth.UserID(c), sid)
	if err != nil {
		return serverError(c, err)
	}
	if !ok {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	logUserEvent(c.Context(), id.db, auth.UserID(c), "session.revoked", c.IP(), map[string]any{"session_id": sid})
	return c.Status(204).Send(nil)
}

func (id *identity) logout(c *fiber.Ctx) error {
	cur, _ := auth.CurrentSession(c)
	if _, err := id.sessions.Revoke(c.Context(), auth.UserID(c), cur.ID); err != nil {
		return serverError(c, err)
	}
	return c.Status(204).Send(nil)
}

func validNewPassword(pw string) error {
	if len(pw) < minPasswordLen || len(pw) > maxPasswordLen {
		return errors.New("password must be 12 to 72 bytes long")
	}
	return nil
}

func (id *identity) changePassword(c *fiber.Ctx) error {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validNewPassword(req.NewPassword); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	user := auth.UserID(c)
	ctx := c.Context()
	var hash *string
	if err := id.db.QueryRow(ctx, `SELECT hashed_password FROM users WHERE id = $1`, user).Scan(&hash); err != nil {
		return serverError(c, err)
	}
	if hash == nil {
		// Setting a first password would give whoever holds this session a
		// login that outlives it; an SSO-only account keeps SSO.
		return auth.Deny(c, fiber.StatusConflict, "no_password", "this account signs in with SSO and has no password")
	}
	if !auth.CheckPassword(*hash, req.CurrentPassword) {
		return auth.Deny(c, fiber.StatusUnauthorized, "invalid_credentials", "the current password is wrong")
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		return serverError(c, err)
	}
	if _, err := id.db.Exec(ctx, `UPDATE users SET hashed_password = $2 WHERE id = $1`, user, newHash); err != nil {
		return serverError(c, err)
	}
	cur, _ := auth.CurrentSession(c)
	if _, err := id.sessions.RevokeAll(ctx, user, cur.ID); err != nil {
		return serverError(c, err)
	}
	logUserEvent(ctx, id.db, user, "password.changed", c.IP(), nil)
	return c.Status(204).Send(nil)
}
