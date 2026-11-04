//go:build integration

package main

import (
	"context"
	"errors"
	"net/url"
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

// Integration run of #25 + #26.

// A save of the security page without restricting methods keeps the org
// unrestricted: an SSO provider added later is not refused.
func TestLoginMethodsStayUnrestricted(t *testing.T) {
	h := newCPHarness(t)
	org, _, owner := h.org(auth.RoleOwner)
	base := "/v1/organizations/" + org.String() + "/security"
	sec := h.expect(200, "GET", base, owner, "")
	if sec["allowed_login_methods"] != nil {
		t.Fatalf("unrestricted org: %v", sec["allowed_login_methods"])
	}
	// The UI sends back what it read (null), and omitting it means the same.
	h.expect(200, "PUT", base, owner, `{"allowed_login_methods":null,"session_lifetime_hours":12}`)
	h.expect(200, "PUT", base, owner, `{"session_lifetime_hours":10}`)
	if sec = h.expect(200, "GET", base, owner, ""); sec["allowed_login_methods"] != nil {
		t.Errorf("pinned after a save: %v", sec["allowed_login_methods"])
	}
	// A provider added afterwards: its sessions reach the org.
	var pid uuid.UUID
	if err := h.db.QueryRow(context.Background(),
		`INSERT INTO identity_providers (type, display_name, issuer, client_id, client_secret_env)
		 VALUES ('oidc', 'Later', 'https://idp.example', 'c', 'OIDC_SECRET_LATER') RETURNING id`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	_, user := h.user("")
	h.addMember(org, user, auth.RoleViewer)
	sess, err := auth.NewSessions(h.db).Create(context.Background(), auth.NewSession{UserID: user, Method: "oidc:" + pid.String()})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := auth.IssueSessionToken(testSecret, user, sess.ID, sess.ExpiresAt)
	h.expect(200, "GET", "/v1/organizations/"+org.String(), tok, "")
	// A disabled provider's method is not a known method.
	if _, err := h.db.Exec(context.Background(), `UPDATE identity_providers SET enabled = false WHERE id = $1`, pid); err != nil {
		t.Fatal(err)
	}
	h.expect(400, "PUT", base, owner, `{"allowed_login_methods":["password","oidc:`+pid.String()+`"]}`)
}

// ?action= matches an action or its family; totals come with the page.
func TestActivityFamilyFilterAndTotals(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	for _, e := range []string{"a@example.com", "b@example.com"} {
		h.expect(201, "POST", "/v1/orgs/"+org.String()+"/invites", admin, `{"email":"`+e+`","role":"viewer"}`)
	}
	h.expect(201, "POST", "/v1/organizations/"+org.String()+"/api-keys", admin, `{"alias":"k"}`)
	writeActivity(context.Background(), h.db, activityEntry{Org: &org, Action: "invitex.other"})
	writeActivity(context.Background(), h.db, activityEntry{Org: &org, Action: "inv%te.wild"})
	act := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/activity?action=invite&limit=1", admin, "")
	if act["total"] != float64(2) || act["total_capped"] != false || len(act["items"].([]any)) != 1 || act["next_cursor"] == nil {
		t.Errorf("family filter: %v", act)
	}
	if act := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/activity?action=invite.created", admin, ""); act["total"] != float64(2) {
		t.Errorf("exact action: %v", act)
	}
	if act := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/activity?action=inv%25te", admin, ""); act["total"] != float64(1) {
		t.Errorf("LIKE characters must be literal: %v", act)
	}
}

// A target that is a user id comes with the user's email (target_label).
func TestActivityTargetLabel(t *testing.T) {
	h := newCPHarness(t)
	org, user, admin := h.org(auth.RoleAdmin)
	var email string
	if err := h.db.QueryRow(context.Background(), `SELECT email FROM users WHERE id = $1`, user).Scan(&email); err != nil {
		t.Fatal(err)
	}
	writeActivity(context.Background(), h.db, activityEntry{Org: &org, Action: "project_member.role_changed", Target: user.String()})
	writeActivity(context.Background(), h.db, activityEntry{Org: &org, Action: "upstream.tested", Target: "prod-up"})
	act := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/activity?limit=10", admin, "")
	labels := map[string]any{}
	for _, it := range act["items"].([]any) {
		row := it.(map[string]any)
		labels[row["action"].(string)] = row["target_label"]
	}
	if labels["project_member.role_changed"] != email {
		t.Errorf("user target: %v, want %s", labels["project_member.role_changed"], email)
	}
	if labels["upstream.tested"] != nil {
		t.Errorf("a name target gets no label: %v", labels["upstream.tested"])
	}
}

func TestRequestsAndKeysFilters(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	ctx := context.Background()
	err := withOrgTx(h, org, func(tx pgx.Tx) error {
		for _, q := range []string{
			`INSERT INTO requests (org_id, action, model, route_target, injection_label) VALUES ($1, 'block', 'gpt-4o', 'prod-up', 'jailbreak')`,
			`INSERT INTO requests (org_id, action, model, request_content) VALUES ($1, 'allow', 'llama3', 'secret prompt jailbreak')`,
		} {
			if _, err := tx.Exec(ctx, q, org); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/organizations/" + org.String() + "/requests?limit=10"
	all := h.expect(200, "GET", base, admin, "")
	if all["total"] != float64(2) || all["total_capped"] != false {
		t.Errorf("requests total: %v", all)
	}
	for q, want := range map[string]float64{"JAILBREAK": 1, "prod-UP": 1, "llama": 1, "block": 1, "secret prompt": 0} {
		out := h.expect(200, "GET", base+"&q="+url.QueryEscape(q), admin, "")
		if out["total"] != want || float64(len(out["items"].([]any))) != want {
			t.Errorf("q=%q: %v", q, out)
		}
	}

	keys := "/v1/organizations/" + org.String() + "/api-keys"
	h.expect(201, "POST", keys, admin, `{"alias":"Billing service"}`)
	gone := h.expect(201, "POST", keys, admin, `{"alias":"old"}`)
	h.expect(204, "DELETE", keys+"/"+gone["key_prefix"].(string), admin, "")
	check := func(query string, want float64) {
		t.Helper()
		out := h.expect(200, "GET", keys+"?limit=10&"+query, admin, "")
		if out["total"] != want || float64(len(out["items"].([]any))) != want {
			t.Errorf("%s: %v", query, out)
		}
	}
	check("q=billing", 1)
	check("q="+url.QueryEscape(gone["key_prefix"].(string)), 1)
	check("revoked=true", 1)
	check("revoked=false", 1)
	check("revoked=false&q=old", 0)
	h.expect(400, "GET", keys+"?revoked=maybe", admin, "")
}

func withOrgTx(h *cpHarness, org uuid.UUID, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(context.Background(), h.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `SELECT set_config('app.org_id', $1, true)`, org.String()); err != nil {
			return err
		}
		return fn(tx)
	})
}
