package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

// SSO with OpenID Connect, Google as a preset (migration 013).
//
// Providers are instance-wide (a login happens before an org is known) and
// managed by instance administrators. The client secret is read from the
// environment variable client_secret_env names (OIDC_SECRET_*), never stored.
//
// GET /auth/oidc/:id/start stores a state (as its SHA-256), a nonce and a
// PKCE verifier for 10 minutes and redirects to the provider. The callback
// takes the state once, exchanges the code with the verifier, verifies the
// ID token (signature through JWKS, issuer, audience, expiry, nonce) and
// email_verified, then links or creates the user and redirects the browser to
// /ui/#/auth/callback?code=<one-time 60 s code>; POST /auth/oidc/exchange
// turns that code into the same answer as a password login. Tokens never go
// in URLs.
//
// Account takeover: an identity is matched on (provider, subject). An email
// match links to an existing account only if that account has no password
// (or the user links from their logged-in profile); otherwise the login is
// refused with account_exists.

const (
	googleIssuer  = "https://accounts.google.com"
	oidcStateTTL  = 10 * time.Minute
	oidcCodeTTL   = 60 * time.Second
	callbackPath  = "/ui/#/auth/callback"
	defaultReturn = "/ui/"
)

var (
	secretEnvRe = regexp.MustCompile(`^OIDC_SECRET_[A-Z0-9_]{1,64}$`)
	scopeRe     = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]{1,64}$`)
	domainRe    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

type providerRow struct {
	ID              uuid.UUID `json:"id"`
	Type            string    `json:"type"`
	DisplayName     string    `json:"display_name"`
	Issuer          string    `json:"issuer"`
	ClientID        string    `json:"client_id"`
	ClientSecretEnv string    `json:"client_secret_env"`
	Scopes          []string  `json:"scopes"`
	AllowedDomains  []string  `json:"allowed_domains"`
	AutoProvision   bool      `json:"auto_provision"`
	// TrustEmailForLinking lets a first login link to an existing account
	// with the same verified email, if that account has no password and no
	// identity. Off: such a login is refused with account_exists.
	TrustEmailForLinking bool      `json:"trust_email_for_linking"`
	Enabled              bool      `json:"enabled"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

const providerColumns = `id, type, display_name, issuer, client_id, client_secret_env, scopes, allowed_domains,
	auto_provision, trust_email_for_linking, enabled, created_at, updated_at`

func scanProvider(row pgx.Row) (providerRow, error) {
	var p providerRow
	err := row.Scan(&p.ID, &p.Type, &p.DisplayName, &p.Issuer, &p.ClientID, &p.ClientSecretEnv, &p.Scopes,
		&p.AllowedDomains, &p.AutoProvision, &p.TrustEmailForLinking, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// method is the login method of a session from this provider.
func (p providerRow) method() string {
	if p.Type == "google" {
		return auth.MethodGoogle
	}
	return "oidc:" + p.ID.String()
}

// validIssuer accepts https, and http for a loopback host (development and tests).
func validIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("issuer must be an absolute https url")
	}
	host := u.Hostname()
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
		return errors.New("issuer must be an https url")
	}
	return nil
}

func (p *providerRow) validate() error {
	switch p.Type {
	case "google":
		if p.Issuer == "" {
			p.Issuer = googleIssuer
		}
		if p.DisplayName == "" {
			p.DisplayName = "Google"
		}
	case "oidc":
	default:
		return errors.New("type must be google or oidc")
	}
	p.DisplayName = strings.TrimSpace(p.DisplayName)
	if p.DisplayName == "" || len([]rune(p.DisplayName)) > 100 {
		return errors.New("display_name must be 1 to 100 characters")
	}
	if len(p.Issuer) > 2048 {
		return errors.New("issuer is too long")
	}
	if err := validIssuer(p.Issuer); err != nil {
		return err
	}
	if p.ClientID == "" || len(p.ClientID) > 512 {
		return errors.New("client_id is required")
	}
	if !secretEnvRe.MatchString(p.ClientSecretEnv) {
		return errors.New("client_secret_env must match ^OIDC_SECRET_[A-Z0-9_]{1,64}$")
	}
	if len(p.Scopes) == 0 {
		p.Scopes = []string{"openid", "email", "profile"}
	}
	if len(p.Scopes) > 20 || !slices.Contains(p.Scopes, "openid") || !slices.Contains(p.Scopes, "email") {
		return errors.New("scopes must include openid and email (at most 20)")
	}
	for _, s := range p.Scopes {
		if !scopeRe.MatchString(s) {
			return fmt.Errorf("scope %q is not valid", s)
		}
	}
	if p.AllowedDomains == nil {
		p.AllowedDomains = []string{}
	}
	if len(p.AllowedDomains) > 100 {
		return errors.New("at most 100 allowed_domains")
	}
	for i, d := range p.AllowedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !domainRe.MatchString(d) {
			return fmt.Errorf("allowed_domains: %q is not a domain", d)
		}
		p.AllowedDomains[i] = d
	}
	return nil
}

// ── Provider cache ───────────────────────────────────────────────────────────

type oidcProvider struct {
	row      providerRow
	verifier *oidc.IDTokenVerifier
	config   oauth2.Config
}

var errProviderUnavailable = errors.New("this sign-in provider is not available")

func (id *identity) loadProvider(ctx context.Context, pid uuid.UUID) (providerRow, error) {
	p, err := scanProvider(id.db.QueryRow(ctx, `SELECT `+providerColumns+` FROM identity_providers WHERE id = $1`, pid))
	if errors.Is(err, pgx.ErrNoRows) {
		return p, errProviderUnavailable
	}
	return p, err
}

func (id *identity) callbackURL(pid uuid.UUID) string {
	return id.publicURL + "/v1/auth/oidc/" + pid.String() + "/callback"
}

// provider returns the enabled provider pid, discovering it on first use and
// again after the row changes.
func (id *identity) provider(ctx context.Context, pid uuid.UUID) (*oidcProvider, error) {
	row, err := id.loadProvider(ctx, pid)
	if err != nil {
		return nil, err
	}
	if !row.Enabled {
		return nil, errProviderUnavailable
	}
	if id.publicURL == "" {
		return nil, errors.New("PUBLIC_BASE_URL is not set; SSO needs it for the callback url")
	}
	secret := os.Getenv(row.ClientSecretEnv)
	if secret == "" {
		return nil, fmt.Errorf("%s is not set", row.ClientSecretEnv)
	}
	id.oidcMu.Lock()
	cached, ok := id.providers[pid]
	id.oidcMu.Unlock()
	if ok && cached.row.UpdatedAt.Equal(row.UpdatedAt) && cached.config.ClientSecret == secret {
		return cached, nil
	}
	dctx, cancel := context.WithTimeout(oidc.ClientContext(context.Background(), id.client), 10*time.Second)
	defer cancel()
	prov, err := oidc.NewProvider(dctx, row.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery of %s: %w", row.Issuer, err)
	}
	op := &oidcProvider{
		row:      row,
		verifier: prov.Verifier(&oidc.Config{ClientID: row.ClientID}),
		config: oauth2.Config{ClientID: row.ClientID, ClientSecret: secret, Endpoint: prov.Endpoint(),
			RedirectURL: id.callbackURL(pid), Scopes: row.Scopes},
	}
	id.oidcMu.Lock()
	id.providers[pid] = op
	id.oidcMu.Unlock()
	return op, nil
}

// ── Public endpoints ─────────────────────────────────────────────────────────

// publicProviders lists the enabled providers for the login page.
func (id *identity) publicProviders(c *fiber.Ctx) error {
	rows, err := id.db.Query(c.Context(),
		`SELECT id, type, display_name FROM identity_providers WHERE enabled ORDER BY display_name, id`)
	if err != nil {
		return serverError(c, err)
	}
	type row struct {
		ID          uuid.UUID `json:"id"`
		Type        string    `json:"type"`
		DisplayName string    `json:"display_name"`
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		return x, r.Scan(&x.ID, &x.Type, &x.DisplayName)
	})
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(list)
}

// safeRedirect accepts a same-origin path under /ui/.
func safeRedirect(r string) (string, bool) {
	if r == "" {
		return defaultReturn, true
	}
	if len(r) > 512 || !strings.HasPrefix(r, "/ui/") || strings.ContainsAny(r, "\\\r\n\t") ||
		strings.Contains(r, "/../") || strings.Contains(r, "//") {
		return "", false
	}
	return r, true
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ssoCookie binds an SSO login to the browser that started it (login CSRF).
const ssoCookie = "gs_sso"

// beginAuth stores a login in progress and returns the provider's URL.
// browser is the random value of the cookie that start sets ("" for a profile
// link, which is bound to the user at completion instead).
func (id *identity) beginAuth(ctx context.Context, p *oidcProvider, redirect string, linkUser *uuid.UUID, browser string) (string, error) {
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	nonce, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()
	if _, err := id.db.Exec(ctx,
		`INSERT INTO oidc_states (state_hash, provider_id, nonce, code_verifier, redirect, link_user_id, expires_at,
		   browser_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW() + $7::interval, NULLIF($8, ''))`,
		tenant.HashKey(state), p.row.ID, nonce, verifier, redirect, linkUser, oidcStateTTL, hashOrEmpty(browser)); err != nil {
		return "", err
	}
	_, _ = id.db.Exec(ctx, `DELETE FROM oidc_states WHERE expires_at < NOW()`)
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if p.row.Type == "google" && len(p.row.AllowedDomains) == 1 {
		// A hint for Google's account picker; the callback still checks the claim.
		opts = append(opts, oauth2.SetAuthURLParam("hd", p.row.AllowedDomains[0]))
	}
	return p.config.AuthCodeURL(state, opts...), nil
}

func (id *identity) oidcStart(c *fiber.Ctx) error {
	pid, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": errProviderUnavailable.Error()})
	}
	redirect, ok := safeRedirect(c.Query("redirect"))
	if !ok {
		return c.Status(400).JSON(fiber.Map{"error": "redirect must be a path under /ui/"})
	}
	p, err := id.provider(c.Context(), pid)
	if errors.Is(err, errProviderUnavailable) {
		return c.Status(404).JSON(fiber.Map{"error": err.Error()})
	}
	if err != nil {
		slog.Error("sso provider unavailable", "provider", pid, "err", err)
		return auth.Deny(c, fiber.StatusServiceUnavailable, "sso_unavailable", "this sign-in provider is not configured correctly")
	}
	browser, err := randomToken()
	if err != nil {
		return serverError(c, err)
	}
	to, err := id.beginAuth(c.Context(), p, redirect, nil, browser)
	if err != nil {
		return serverError(c, err)
	}
	c.Cookie(&fiber.Cookie{Name: ssoCookie, Value: browser, Path: "/v1/auth/oidc", MaxAge: int(oidcStateTTL.Seconds()),
		HTTPOnly: true, Secure: strings.HasPrefix(id.publicURL, "https://"), SameSite: fiber.CookieSameSiteLaxMode})
	return c.Redirect(to, fiber.StatusFound)
}

// linkStart begins linking an SSO identity to the logged-in user. The answer
// is {"url"}: the UI navigates there (a fetch cannot follow a redirect to
// another origin).
func (id *identity) linkStart(c *fiber.Ctx) error {
	pid, err := uuid.Parse(c.Params("providerId"))
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": errProviderUnavailable.Error()})
	}
	p, err := id.provider(c.Context(), pid)
	if errors.Is(err, errProviderUnavailable) {
		return c.Status(404).JSON(fiber.Map{"error": err.Error()})
	}
	if err != nil {
		slog.Error("sso provider unavailable", "provider", pid, "err", err)
		return auth.Deny(c, fiber.StatusServiceUnavailable, "sso_unavailable", "this sign-in provider is not configured correctly")
	}
	user := auth.UserID(c)
	to, err := id.beginAuth(c.Context(), p, accountPath, &user, "")
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(fiber.Map{"url": to})
}

// accountPath is where a profile link's callback sends the browser.
const accountPath = "/ui/account"

// ssoError ends a callback with an error code for the UI.
func ssoError(c *fiber.Ctx, code string) error {
	return c.Redirect(callbackPath+"?error="+url.QueryEscape(code), fiber.StatusFound)
}

func hashOrEmpty(s string) string {
	if s == "" {
		return ""
	}
	return tenant.HashKey(s)
}

type idClaims struct {
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"` // a bool, or "true" from some providers
	HD            string `json:"hd"`
	Name          string `json:"name"`
}

func (cl idClaims) verified() bool {
	switch v := cl.EmailVerified.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func emailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 1 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

// domainAllowed applies allowed_domains: the email's domain, and for Google
// the hd claim (the Workspace domain), must be listed. Empty allows any
// verified email.
func domainAllowed(p providerRow, email, hd string) bool {
	if len(p.AllowedDomains) == 0 {
		return true
	}
	if !slices.Contains(p.AllowedDomains, emailDomain(email)) {
		return false
	}
	if p.Type == "google" {
		return hd != "" && slices.Contains(p.AllowedDomains, strings.ToLower(hd))
	}
	return true
}

// errSSO is a refused SSO login; code goes to the UI.
type errSSO struct{ code string }

func (e *errSSO) Error() string { return "sso: " + e.code }

func (id *identity) oidcCallback(c *fiber.Ctx) error {
	ctx := c.Context()
	pid, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return ssoError(c, "invalid_state")
	}
	state := c.Query("state")
	if state == "" {
		return ssoError(c, "invalid_state")
	}
	// The state is taken once, whatever happens next.
	var nonce, verifier, redirect string
	var linkUser *uuid.UUID
	var browserHash *string
	err = id.db.QueryRow(ctx,
		`DELETE FROM oidc_states WHERE state_hash = $1 AND provider_id = $2 AND expires_at > NOW()
		 RETURNING nonce, code_verifier, redirect, link_user_id, browser_hash`, tenant.HashKey(state), pid).
		Scan(&nonce, &verifier, &redirect, &linkUser, &browserHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ssoError(c, "invalid_state")
	}
	if err != nil {
		return serverError(c, err)
	}
	// A login must come back to the browser that started it: otherwise an
	// attacker could log a victim into the attacker's account (login CSRF).
	// A profile link is bound to its user when it is completed instead.
	if linkUser == nil {
		c.ClearCookie(ssoCookie)
		got := c.Cookies(ssoCookie)
		if browserHash == nil || got == "" ||
			subtle.ConstantTimeCompare([]byte(tenant.HashKey(got)), []byte(*browserHash)) != 1 {
			return ssoError(c, "invalid_state")
		}
	}
	// From here on a profile link reports to the account page.
	fail := func(code string) error {
		if linkUser != nil {
			return c.Redirect(accountPath+"?link_error="+url.QueryEscape(code), fiber.StatusFound)
		}
		return ssoError(c, code)
	}
	if e := c.Query("error"); e != "" {
		return fail("provider_error")
	}
	p, err := id.provider(ctx, pid)
	if err != nil {
		slog.Warn("sso callback: provider unavailable", "provider", pid, "err", err)
		return fail("sso_unavailable")
	}
	hctx, cancel := context.WithTimeout(oidc.ClientContext(context.Background(), id.client), 15*time.Second)
	defer cancel()
	tok, err := p.config.Exchange(hctx, c.Query("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		slog.Warn("sso callback: code exchange failed", "provider", pid, "err", err)
		return fail("exchange_failed")
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return fail("invalid_token")
	}
	idt, err := p.verifier.Verify(hctx, rawID)
	if err != nil {
		slog.Warn("sso callback: id token refused", "provider", pid, "err", err)
		return fail("invalid_token")
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		return fail("invalid_nonce")
	}
	var claims idClaims
	if err := idt.Claims(&claims); err != nil {
		return fail("invalid_token")
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" || !claims.verified() || len(idt.Subject) == 0 || len(idt.Subject) > 255 {
		logUserEvent(ctx, id.db, uuid.Nil, "login.failed", clientIP(c), map[string]any{"method": p.row.method(), "reason": "email_not_verified"})
		return fail("email_not_verified")
	}
	if !domainAllowed(p.row, email, claims.HD) {
		logUserEvent(ctx, id.db, uuid.Nil, "login.failed", clientIP(c),
			map[string]any{"method": p.row.method(), "reason": "domain_not_allowed", "domain": emailDomain(email)})
		return fail("domain_not_allowed")
	}

	if linkUser != nil {
		// Not linked yet: whoever's browser this is may not be linkUser (an
		// attacker can send a victim the provider's URL). The UI completes the
		// link with the code and its own token; the user must match.
		code, err := randomToken()
		if err != nil {
			return serverError(c, err)
		}
		if _, err := id.db.Exec(ctx,
			`INSERT INTO oidc_codes (code_hash, user_id, method, redirect, expires_at, purpose, provider_id, subject, email)
			 VALUES ($1, $2, $3, $4, NOW() + $5::interval, 'link', $6, $7, $8)`,
			tenant.HashKey(code), *linkUser, p.row.method(), accountPath, oidcCodeTTL, pid, idt.Subject, email); err != nil {
			return serverError(c, err)
		}
		return c.Redirect(accountPath+"?link_code="+url.QueryEscape(code), fiber.StatusFound)
	}

	user, err := id.ssoUser(ctx, p.row, idt.Subject, email, claims.Name)
	var se *errSSO
	if errors.As(err, &se) {
		logUserEvent(ctx, id.db, user, "login.failed", clientIP(c), map[string]any{"method": p.row.method(), "reason": se.code})
		return ssoError(c, se.code)
	}
	if err != nil {
		return serverError(c, err)
	}
	code, err := randomToken()
	if err != nil {
		return serverError(c, err)
	}
	if _, err := id.db.Exec(ctx,
		`INSERT INTO oidc_codes (code_hash, user_id, method, redirect, expires_at, purpose)
		 VALUES ($1, $2, $3, $4, NOW() + $5::interval, 'login')`,
		tenant.HashKey(code), user, p.row.method(), redirect, oidcCodeTTL); err != nil {
		return serverError(c, err)
	}
	_, _ = id.db.Exec(ctx, `DELETE FROM oidc_codes WHERE expires_at < NOW() - interval '1 hour'`)
	return c.Redirect(callbackPath+"?code="+url.QueryEscape(code), fiber.StatusFound)
}

// ssoUser returns the user an SSO login is for, linking or creating it as the
// rules allow, and applies the organizations' domain_join rules to a new link.
func (id *identity) ssoUser(ctx context.Context, p providerRow, subject, email, name string) (uuid.UUID, error) {
	var user uuid.UUID
	err := pgx.BeginFunc(ctx, id.db, func(tx pgx.Tx) error {
		var disabled *time.Time
		err := tx.QueryRow(ctx,
			`SELECT u.id, u.disabled_at FROM user_identities i JOIN users u ON u.id = i.user_id
			 WHERE i.provider_id = $1 AND i.subject = $2`, p.ID, subject).Scan(&user, &disabled)
		if err == nil {
			if disabled != nil {
				return &errSSO{"account_disabled"}
			}
			_, err = tx.Exec(ctx, `UPDATE user_identities SET email = $3 WHERE provider_id = $1 AND subject = $2`,
				p.ID, subject, email)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var hasPassword, hasIdentity bool
		err = tx.QueryRow(ctx,
			`SELECT u.id, u.hashed_password IS NOT NULL, EXISTS (SELECT 1 FROM user_identities i WHERE i.user_id = u.id),
			        u.disabled_at
			 FROM users u WHERE u.email = $1 FOR UPDATE`, email).Scan(&user, &hasPassword, &hasIdentity, &disabled)
		switch {
		case err == nil:
			// An existing account is linked by email only if the provider is
			// trusted for that and the account has no other way in (no
			// password, no identity): otherwise whoever controls this email
			// at the provider would take it over. Its owner links from the
			// profile instead.
			if !p.TrustEmailForLinking || hasPassword || hasIdentity {
				return &errSSO{"account_exists"}
			}
			if disabled != nil {
				return &errSSO{"account_disabled"}
			}
		case errors.Is(err, pgx.ErrNoRows):
			if !p.AutoProvision {
				return &errSSO{"not_provisioned"}
			}
			var display *string
			if n := strings.TrimSpace(name); n != "" {
				n = truncateRunes(n, 200)
				display = &n
			}
			if err := tx.QueryRow(ctx, `INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id`,
				email, display).Scan(&user); err != nil {
				return err
			}
		default:
			return err
		}
		tag, err := tx.Exec(ctx,
			`INSERT INTO user_identities (user_id, provider_id, subject, email) VALUES ($1, $2, $3, $4)
			 ON CONFLICT DO NOTHING`, user, p.ID, subject, email)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return &errSSO{"account_exists"} // the account has another identity at this provider
		}
		return applyDomainJoin(ctx, tx, user, p.ID, email)
	})
	return user, err
}

// linkComplete binds the identity of a profile link to the caller, who must
// be the user who started it. A manual link does not run domain_join.
func (id *identity) linkComplete(c *fiber.Ctx) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.Code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "code is required"})
	}
	user := auth.UserID(c)
	ctx := c.Context()
	var owner, pid uuid.UUID
	var subject, email string
	err := id.db.QueryRow(ctx,
		`SELECT user_id, provider_id, subject, email FROM oidc_codes
		 WHERE code_hash = $1 AND purpose = 'link' AND used_at IS NULL AND expires_at > NOW()`, tenant.HashKey(req.Code)).
		Scan(&owner, &pid, &subject, &email)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Deny(c, fiber.StatusBadRequest, "link_expired", "this link code is invalid, expired or already used; start again")
	}
	if err != nil {
		return serverError(c, err)
	}
	if owner != user {
		// Someone else started this link: the URL was sent to this user.
		return auth.Deny(c, fiber.StatusConflict, "link_wrong_user", "this link was started by another account")
	}
	tag, err := id.db.Exec(ctx, `UPDATE oidc_codes SET used_at = NOW() WHERE code_hash = $1 AND used_at IS NULL`,
		tenant.HashKey(req.Code))
	if err != nil {
		return serverError(c, err)
	}
	if tag.RowsAffected() != 1 {
		return auth.Deny(c, fiber.StatusBadRequest, "link_expired", "this link code was already used")
	}
	err = id.linkIdentity(ctx, user, pid, subject, email)
	var se *errSSO
	if errors.As(err, &se) {
		return auth.Deny(c, fiber.StatusConflict, se.code, "this identity cannot be linked to your account")
	}
	if err != nil {
		return serverError(c, err)
	}
	var display string
	if err := id.db.QueryRow(ctx, `SELECT display_name FROM identity_providers WHERE id = $1`, pid).Scan(&display); err != nil {
		return serverError(c, err)
	}
	logUserEvent(ctx, id.db, user, "identity.linked", clientIP(c), map[string]any{"provider_id": pid})
	return c.JSON(fiber.Map{"provider_id": pid, "display_name": display, "email": email})
}

// applyDomainJoin adds a newly linked SSO user to the organizations whose
// domain_join rule matches the verified email's domain and the provider.
func applyDomainJoin(ctx context.Context, tx pgx.Tx, user, provider uuid.UUID, email string) error {
	rows, err := tx.Query(ctx, `SELECT org_id, role::text FROM domain_join_orgs($1, $2)`, emailDomain(email), provider)
	if err != nil {
		return err
	}
	type join struct {
		org  uuid.UUID
		role string
	}
	joins, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (join, error) {
		var j join
		return j, r.Scan(&j.org, &j.role)
	})
	if err != nil {
		return err
	}
	for _, j := range joins {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.org_id', $1, true)`, j.org.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, $3::org_role) ON CONFLICT DO NOTHING`,
			user, j.org, j.role); err != nil {
			return err
		}
	}
	return nil
}

// linkIdentity binds an SSO identity to a logged-in user. It grants no
// organization: domain_join applies to SSO logins, not to manual links.
func (id *identity) linkIdentity(ctx context.Context, user uuid.UUID, provider uuid.UUID, subject, email string) error {
	return pgx.BeginFunc(ctx, id.db, func(tx pgx.Tx) error {
		var owner uuid.UUID
		err := tx.QueryRow(ctx, `SELECT user_id FROM user_identities WHERE provider_id = $1 AND subject = $2`,
			provider, subject).Scan(&owner)
		switch {
		case err == nil && owner == user:
			return nil
		case err == nil:
			return &errSSO{"identity_in_use"}
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		tag, err := tx.Exec(ctx,
			`INSERT INTO user_identities (user_id, provider_id, subject, email) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			user, provider, subject, email)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return &errSSO{"identity_exists"}
		}
		return nil
	})
}

// oidcExchange turns the callback's one-time code into a login answer.
func (id *identity) oidcExchange(c *fiber.Ctx) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.Code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "code is required"})
	}
	var user uuid.UUID
	var method, redirect string
	var disabled *time.Time
	err := id.db.QueryRow(c.Context(),
		`UPDATE oidc_codes o SET used_at = NOW() FROM users u
		 WHERE o.code_hash = $1 AND o.purpose = 'login' AND o.used_at IS NULL AND o.expires_at > NOW() AND u.id = o.user_id
		 RETURNING o.user_id, o.method, o.redirect, u.disabled_at`, tenant.HashKey(req.Code)).
		Scan(&user, &method, &redirect, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Deny(c, fiber.StatusUnauthorized, "invalid_code", "invalid, expired or already used code")
	}
	if err != nil {
		return serverError(c, err)
	}
	if disabled != nil {
		return auth.Deny(c, fiber.StatusForbidden, "account_disabled", "this account is disabled")
	}
	return id.completeLogin(c, user, method, fiber.Map{"redirect": redirect})
}

// unlinkIdentity removes an SSO identity, unless it is the user's last way in.
func (id *identity) unlinkIdentity(c *fiber.Ctx) error {
	pid, err := uuid.Parse(c.Params("providerId"))
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	user := auth.UserID(c)
	var removed bool
	err = pgx.BeginFunc(c.Context(), id.db, func(tx pgx.Tx) error {
		var hasPassword bool
		var others int
		if err := tx.QueryRow(c.Context(),
			`SELECT u.hashed_password IS NOT NULL,
			        (SELECT count(*) FROM user_identities i WHERE i.user_id = u.id AND i.provider_id <> $2)
			 FROM users u WHERE u.id = $1 FOR UPDATE`, user, pid).Scan(&hasPassword, &others); err != nil {
			return err
		}
		if !hasPassword && others == 0 {
			return &errSSO{"last_login_method"}
		}
		tag, err := tx.Exec(c.Context(), `DELETE FROM user_identities WHERE user_id = $1 AND provider_id = $2`, user, pid)
		removed = tag.RowsAffected() > 0
		return err
	})
	var se *errSSO
	if errors.As(err, &se) {
		return auth.Deny(c, fiber.StatusConflict, se.code, "this is your only way to log in; set a password or link another identity first")
	}
	if err != nil {
		return serverError(c, err)
	}
	if !removed {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	logUserEvent(c.Context(), id.db, user, "identity.unlinked", clientIP(c), map[string]any{"provider_id": pid})
	return c.Status(204).Send(nil)
}

// ── Instance admin: identity providers ───────────────────────────────────────

func (id *identity) listProviders(c *fiber.Ctx) error {
	rows, err := id.db.Query(c.Context(), `SELECT `+providerColumns+` FROM identity_providers ORDER BY created_at, id`)
	if err != nil {
		return serverError(c, err)
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (providerRow, error) { return scanProvider(r) })
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(fiber.Map{"items": list, "next_cursor": nil, "total": len(list)})
}

func (id *identity) createProvider(c *fiber.Ctx) error {
	p := providerRow{Enabled: true}
	if err := json.Unmarshal(c.Body(), &p); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := p.validate(); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	p, err := scanProvider(id.db.QueryRow(c.Context(),
		`INSERT INTO identity_providers (type, display_name, issuer, client_id, client_secret_env, scopes,
		   allowed_domains, auto_provision, trust_email_for_linking, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING `+providerColumns,
		p.Type, p.DisplayName, p.Issuer, p.ClientID, p.ClientSecretEnv, p.Scopes, p.AllowedDomains,
		p.AutoProvision, p.TrustEmailForLinking, p.Enabled))
	if err != nil {
		return serverError(c, err)
	}
	logActivity(c, id.db, nil, "identity_provider.created", p.DisplayName, map[string]any{"id": p.ID, "type": p.Type})
	return c.Status(201).JSON(p)
}

func (id *identity) updateProvider(c *fiber.Ctx) error {
	pid, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	p, err := id.loadProvider(c.Context(), pid)
	if errors.Is(err, errProviderUnavailable) {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	if err != nil {
		return serverError(c, err)
	}
	typ := p.Type
	if err := json.Unmarshal(c.Body(), &p); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	p.ID = pid
	if p.Type != typ {
		return c.Status(400).JSON(fiber.Map{"error": "type cannot be changed"})
	}
	if err := p.validate(); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	p, err = scanProvider(id.db.QueryRow(c.Context(),
		`UPDATE identity_providers SET display_name = $2, issuer = $3, client_id = $4, client_secret_env = $5,
		   scopes = $6, allowed_domains = $7, auto_provision = $8, enabled = $9, trust_email_for_linking = $10,
		   updated_at = NOW()
		 WHERE id = $1 RETURNING `+providerColumns,
		pid, p.DisplayName, p.Issuer, p.ClientID, p.ClientSecretEnv, p.Scopes, p.AllowedDomains, p.AutoProvision, p.Enabled,
		p.TrustEmailForLinking))
	if err != nil {
		return serverError(c, err)
	}
	logActivity(c, id.db, nil, "identity_provider.updated", p.DisplayName,
		map[string]any{"id": p.ID, "enabled": p.Enabled, "auto_provision": p.AutoProvision,
			"trust_email_for_linking": p.TrustEmailForLinking})
	return c.JSON(p)
}

func (id *identity) deleteProvider(c *fiber.Ctx) error {
	pid, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	// Users who can log in only through this provider would be locked out.
	var stranded int
	if err := id.db.QueryRow(c.Context(),
		`SELECT count(*) FROM user_identities i JOIN users u ON u.id = i.user_id
		 WHERE i.provider_id = $1 AND u.hashed_password IS NULL AND u.disabled_at IS NULL
		   AND NOT EXISTS (SELECT 1 FROM user_identities o WHERE o.user_id = u.id AND o.provider_id <> $1)`, pid).
		Scan(&stranded); err != nil {
		return serverError(c, err)
	}
	if stranded > 0 && c.Query("force") != "true" {
		return auth.Deny(c, fiber.StatusConflict, "provider_in_use",
			fmt.Sprintf("%d users log in only through this provider; disable it instead, or delete with ?force=true", stranded))
	}
	tag, err := id.db.Exec(c.Context(), `DELETE FROM identity_providers WHERE id = $1`, pid)
	if err != nil {
		return serverError(c, err)
	}
	if tag.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	id.oidcMu.Lock()
	delete(id.providers, pid)
	id.oidcMu.Unlock()
	logActivity(c, id.db, nil, "identity_provider.deleted", pid.String(), map[string]any{"id": pid, "stranded_users": stranded})
	return c.Status(204).Send(nil)
}
