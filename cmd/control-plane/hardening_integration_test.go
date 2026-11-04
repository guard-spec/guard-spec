//go:build integration

package main

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Regression tests for the security review of the identity work (RF-N15).

// 2FA and sessions belong to the user across orgs: an owner of one shared org
// cannot reset them.
func TestResetMFANeedsSoleAuthority(t *testing.T) {
	h := newCPHarness(t)
	orgA, _, ownerA := h.org(auth.RoleOwner)
	victim := h.passwordUser(uniqueEmail(), "victim-password-12")
	h.addMember(orgA, victim, auth.RoleMember)
	// The victim is also in an org the attacker does not own.
	orgB, _, _ := h.org(auth.RoleOwner)
	h.addMember(orgB, victim, auth.RoleViewer)
	base := "/v1/organizations/" + orgA.String() + "/members/" + victim.String()
	for _, action := range []string{"/reset-mfa", "/revoke-sessions"} {
		if status, out := h.do("POST", base+action, ownerA, ""); status != 403 || out["code"] != "not_sole_authority" {
			t.Errorf("%s by an owner of one org: %d %v", action, status, out)
		}
	}
	// An instance administrator may (they also need a role in the org's route).
	adminTok, adminID := h.instanceAdmin()
	h.addMember(orgA, adminID, auth.RoleOwner)
	h.expect(204, "POST", base+"/reset-mfa", adminTok, "")
	h.expect(200, "POST", base+"/revoke-sessions", adminTok, "")
	// An owner of every org of the target may.
	solo := h.passwordUser(uniqueEmail(), "solo-password-123")
	h.addMember(orgA, solo, auth.RoleViewer)
	h.expect(204, "POST", "/v1/organizations/"+orgA.String()+"/members/"+solo.String()+"/reset-mfa", ownerA, "")
}

// Emails are stored lower-cased; logins and invites match case-insensitively.
func TestEmailNormalized(t *testing.T) {
	h := newCPHarness(t)
	email := uniqueEmail()
	h.passwordUser(email, "normal-password-12")
	h.expect(200, "POST", "/v1/auth/login", "", loginBody(strings.ToUpper(email)+" ", "normal-password-12"))
	if _, err := h.db.Exec(context.Background(), `INSERT INTO users (email) VALUES ($1)`, "Mixed@Example.com"); err == nil {
		t.Error("an email with capitals was stored")
	}
}

// An SSO login links to an existing account by email only with
// trust_email_for_linking, and only to an account with no password and no
// identity.
func TestSSOEmailLinkNeedsTrust(t *testing.T) {
	idp := newFakeIDP(t)
	t.Setenv("OIDC_SECRET_TEST", "client-secret-for-tests")
	h := newCPHarness(t, func(s *appSettings) { s.publicURL = "http://cp.test" })
	admin, _ := h.instanceAdmin()
	domain := "trust-" + uuid.NewString()[:8] + ".example"
	prov := h.expect(201, "POST", "/v1/admin/identity-providers", admin,
		`{"type":"oidc","display_name":"T","issuer":"`+idp.URL+`","client_id":"guard-spec","client_secret_env":"OIDC_SECRET_TEST",
		  "allowed_domains":["`+domain+`"],"auto_provision":true}`)
	pid := prov["id"].(string)
	if prov["trust_email_for_linking"] != false {
		t.Errorf("trust defaults on: %v", prov)
	}
	claims := func(nonce, sub, email string) map[string]any {
		return map[string]any{"iss": idp.URL, "aud": "guard-spec", "sub": sub, "email": email, "email_verified": true,
			"nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	}
	login := func(sub, email string) string {
		run := h.ssoStart(pid, "/ui/")
		code := uuid.NewString()
		idp.grant(code, run.challenge, claims(run.nonce, sub, email))
		cb := h.ssoCallback(pid, run, code)
		if e := cb.Get("error"); e != "" {
			return e
		}
		return "ok"
	}
	// A password-less account (an invitee who never set one, say).
	bare := "bare-" + uuid.NewString()[:6] + "@" + domain
	if _, err := h.db.Exec(context.Background(), `INSERT INTO users (email) VALUES ($1)`, bare); err != nil {
		t.Fatal(err)
	}
	if got := login("sub-bare", bare); got != "account_exists" {
		t.Errorf("untrusted provider linked by email: %s", got)
	}
	h.expect(200, "PUT", "/v1/admin/identity-providers/"+pid, admin, `{"trust_email_for_linking":true}`)
	if got := login("sub-bare", bare); got != "ok" {
		t.Errorf("trusted provider: %s", got)
	}
	// An account created by SSO has an identity: another subject with the
	// same email does not take it over, trusted or not.
	sso := "sso-" + uuid.NewString()[:6] + "@" + domain
	if got := login("sub-first", sso); got != "ok" {
		t.Fatalf("first SSO login: %s", got)
	}
	if got := login("sub-second", sso); got != "account_exists" {
		t.Errorf("second subject took over an SSO account: %s", got)
	}
	// Capitals from the provider are normalized.
	if got := login("sub-first", strings.ToUpper(sso)); got != "ok" {
		t.Errorf("upper-case email: %s", got)
	}
}

// Wrong codes lock the user's second factor, across mfa_tokens and addresses.
func TestMFAPerUserLockout(t *testing.T) {
	h := newCPHarness(t)
	email := uniqueEmail()
	user := h.passwordUser(email, "lock-password-1234")
	token := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "lock-password-1234"))["token"].(string)
	secret, _, _ := h.enableMFA(token)
	fails := 0
	for fails < mfaLockAfter {
		// A fresh app per round: the per-IP limits are not what stops this.
		h.app = newCPHarness(t).app
		mt := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "lock-password-1234"))["mfa_token"].(string)
		for range maxMFAAttempts {
			if fails == mfaLockAfter {
				break
			}
			if status, _ := h.do("POST", "/v1/auth/mfa/verify", "", `{"mfa_token":"`+mt+`","code":"000000"}`); status != 401 {
				t.Fatalf("wrong code %d: %d", fails, status)
			}
			fails++
		}
	}
	h.app = newCPHarness(t).app
	mt := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "lock-password-1234"))["mfa_token"].(string)
	status, out := h.do("POST", "/v1/auth/mfa/verify", "", `{"mfa_token":"`+mt+`","code":"`+totpNow(t, secret, 1)+`"}`)
	if status != 429 || out["code"] != "mfa_locked" {
		t.Fatalf("locked account accepted a right code: %d %v", status, out)
	}
	var n int
	if err := withInstanceScope(context.Background(), h.db, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM activity_log WHERE org_id IS NULL AND action = 'mfa.locked' AND actor_id = $1`, user).Scan(&n)
	}); err != nil || n != 1 {
		t.Errorf("lockout not logged: %d %v", n, err)
	}
	// After the lock, a right code resets the count.
	if _, err := h.db.Exec(context.Background(), `UPDATE users SET mfa_locked_until = NOW() - interval '1 second' WHERE id = $1`, user); err != nil {
		t.Fatal(err)
	}
	if status, out := h.do("POST", "/v1/auth/mfa/verify", "", `{"mfa_token":"`+mt+`","code":"`+totpNow(t, secret, 1)+`"}`); status != 200 {
		t.Fatalf("after the lock: %d %v", status, out)
	}
	var failures int
	if err := h.db.QueryRow(context.Background(), `SELECT mfa_failures FROM users WHERE id = $1`, user).Scan(&failures); err != nil || failures != 0 {
		t.Errorf("failures not reset: %d %v", failures, err)
	}
}

// Disabled owners do not count as owners; a deleted user loses memberships.
func TestDisabledOwnersAndDeletedMemberships(t *testing.T) {
	h := newCPHarness(t)
	org, ownerID, ownerTok := h.org(auth.RoleOwner)
	ghost := h.passwordUser(uniqueEmail(), "ghost-password-12")
	h.addMember(org, ghost, auth.RoleOwner)
	if _, err := h.db.Exec(context.Background(), `UPDATE users SET disabled_at = NOW() WHERE id = $1`, ghost); err != nil {
		t.Fatal(err)
	}
	// With the only other owner disabled, the active owner is the last one.
	if status, out := h.do("PUT", "/v1/organizations/"+org.String()+"/members/"+ownerID.String(), ownerTok,
		`{"role":"admin"}`); status != 409 || out["code"] != "last_owner" {
		t.Errorf("demote with a disabled co-owner: %d %v", status, out)
	}
	admin, _ := h.instanceAdmin()
	// Deleting or disabling the only active owner of an org is refused.
	if status, out := h.do("DELETE", "/v1/admin/users/"+ownerID.String(), admin, ""); status != 409 || out["code"] != "last_owner" {
		t.Errorf("delete sole owner: %d %v", status, out)
	}
	h.expect(409, "PUT", "/v1/admin/users/"+ownerID.String(), admin, `{"disabled":true}`)
	// A deleted member holds no role anywhere.
	member := h.passwordUser(uniqueEmail(), "member-password-12")
	h.addMember(org, member, auth.RoleAdmin)
	h.expect(204, "DELETE", "/v1/admin/users/"+member.String(), admin, "")
	if role := h.role(member, org); role != "" {
		t.Errorf("deleted user still %s", role)
	}
}

// A bootstrap admin who was deleted is not recreated at the next start.
func TestBootstrapRunsOnce(t *testing.T) {
	ctx := context.Background()
	email := "Boot-" + uuid.NewString()[:8] + "@Example.com"
	hash, _ := auth.HashPassword("bootstrap-password-1")
	// In one transaction of the table owner, rolled back: a fresh instance
	// without admins.
	owner, err := pgxpool.New(ctx, envOr("TEST_OWNER_DATABASE_URL", "postgres://ps:ps@localhost:5432/guardspec?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	err = pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.org_id', $1, true)`, defaultOrgID.String()); err != nil {
			return err
		}
		for _, q := range []string{`UPDATE users SET is_instance_admin = false`, `DELETE FROM instance_state`} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		if err := bootstrapAdminTx(ctx, tx, strings.ToLower(email), hash); err != nil {
			return err
		}
		var id uuid.UUID
		var admin bool
		if err := tx.QueryRow(ctx, `SELECT id, is_instance_admin FROM users WHERE email = $1`, strings.ToLower(email)).
			Scan(&id, &admin); err != nil || !admin {
			t.Errorf("bootstrap admin: %v %v", admin, err)
			return err
		}
		// The admin is deleted (anonymized) and another takes over.
		if _, err := tx.Exec(ctx, `UPDATE users SET email = 'deleted-' || id || '@invalid', disabled_at = NOW(),
			is_instance_admin = false WHERE id = $1`, id); err != nil {
			return err
		}
		if err := bootstrapAdminTx(ctx, tx, strings.ToLower(email), hash); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, strings.ToLower(email)).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Error("the deleted bootstrap admin was created again")
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
}

// Migration 013 promotes only the earliest owner of the default org.
func TestMigrationPromotesOneAdmin(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/013_identity.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	stmt := regexp.MustCompile(`(?s)UPDATE users SET is_instance_admin = true\s+WHERE id = \(.*?LIMIT 1\);`).Find(raw)
	if stmt == nil {
		t.Fatal("promotion statement not found in 013")
	}
	ctx := context.Background()
	owner, err := pgxpool.New(ctx, envOr("TEST_OWNER_DATABASE_URL", "postgres://ps:ps@localhost:5432/guardspec?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	err = pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET is_instance_admin = false`); err != nil {
			return err
		}
		var first, second uuid.UUID
		for i, dst := range []*uuid.UUID{&first, &second} {
			if err := tx.QueryRow(ctx, `INSERT INTO users (email) VALUES ($1) RETURNING id`, uniqueEmail()).Scan(dst); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO org_memberships (user_id, org_id, role, joined_at)
				VALUES ($1, $2, 'owner', '2000-01-01'::timestamptz + $3 * interval '1 day')`, *dst, defaultOrgID, i); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, string(stmt)); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM users WHERE is_instance_admin`)
		if err != nil {
			return err
		}
		admins, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		if len(admins) != 1 || admins[0] != first {
			t.Errorf("promoted %v, want only %v", admins, first)
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
}

// Failed logins keep a masked email, and login events stay out of org logs.
func TestLoginEventsMaskedAndInstanceOnly(t *testing.T) {
	h := newCPHarness(t)
	org, user, _ := h.org(auth.RoleAdmin)
	var email string
	if err := h.db.QueryRow(context.Background(), `SELECT email FROM users WHERE id = $1`, user).Scan(&email); err != nil {
		t.Fatal(err)
	}
	h.expect(401, "POST", "/v1/auth/login", "", loginBody(email, "Typed-Secret-Password-9"))
	h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "existing-password-123"))
	time.Sleep(300 * time.Millisecond) // the failure is written after the answer
	var details string
	err := withInstanceScope(context.Background(), h.db, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT details::text FROM activity_log WHERE org_id IS NULL AND action = 'login.failed' AND actor_id = $1`, user).
			Scan(&details)
	})
	if err != nil || strings.Contains(details, email) || !strings.Contains(details, "***@example.com") ||
		strings.Contains(details, "Typed-Secret") {
		t.Errorf("failed login details %q %v", details, err)
	}
	token, _ := h.sessionToken(user)
	act := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/activity?limit=200", token, "")
	for _, it := range act["items"].([]any) {
		if a := it.(map[string]any)["action"].(string); strings.HasPrefix(a, "login.") {
			t.Errorf("login event in the org log: %v", it)
		}
	}
}

// A disabled account cannot accept an invite.
func TestInviteAcceptDisabled(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	email := uniqueEmail()
	user := h.passwordUser(email, "invitee-password-1")
	if _, err := h.db.Exec(context.Background(), `UPDATE users SET disabled_at = NOW() WHERE id = $1`, user); err != nil {
		t.Fatal(err)
	}
	inv := h.expect(201, "POST", "/v1/orgs/"+org.String()+"/invites", admin, `{"email":"`+email+`","role":"viewer"}`)
	if status, out := h.do("POST", "/v1/invites/accept", "", `{"token":"`+inv["token"].(string)+`","password":"invitee-password-1"}`); status != 403 ||
		out["code"] != "account_disabled" {
		t.Errorf("disabled accept: %d %v", status, out)
	}
	if h.role(user, org) != "" {
		t.Error("membership added")
	}
}
