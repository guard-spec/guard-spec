//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/config"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// req sends a request and returns the raw response (redirects not followed).
func (h *cpHarness) req(method, path, token, body string) *http.Response {
	h.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.app.Test(r, -1)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// expect runs h.do and fails unless the status is want.
func (h *cpHarness) expect(want int, method, path, token, body string) map[string]any {
	h.t.Helper()
	status, out := h.do(method, path, token, body)
	if status != want {
		h.t.Fatalf("%s %s: status %d, want %d: %v", method, path, status, want, out)
	}
	return out
}

func (h *cpHarness) passwordUser(email, password string) uuid.UUID {
	h.t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		h.t.Fatal(err)
	}
	var id uuid.UUID
	if err := h.db.QueryRow(context.Background(),
		`INSERT INTO users (email, hashed_password) VALUES ($1, $2) RETURNING id`, email, hash).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *cpHarness) addMember(org, user uuid.UUID, role auth.Role) {
	h.t.Helper()
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, $3::org_role)`, user, org, string(role))
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *cpHarness) setSecurity(org uuid.UUID, sql string, args ...any) {
	h.t.Helper()
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, append([]any{org}, args...)...)
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func uniqueEmail() string { return "u-" + uuid.NewString()[:8] + "@example.com" }

func totpNow(t *testing.T, secret string, delta int64) string {
	t.Helper()
	code, err := auth.TOTPCode(secret, auth.TOTPStep(time.Now())+delta)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// enableMFA turns on 2FA for the session token and returns the secret, the
// recovery codes and the TOTP code the setup was confirmed with.
func (h *cpHarness) enableMFA(token string) (string, []string, string) {
	h.t.Helper()
	setup := h.expect(200, "POST", "/v1/auth/mfa/totp/setup", token, `{}`)
	secret := setup["secret"].(string)
	if !strings.HasPrefix(setup["otpauth_url"].(string), "otpauth://totp/") {
		h.t.Fatalf("otpauth_url %v", setup["otpauth_url"])
	}
	used := totpNow(h.t, secret, 0)
	conf := h.expect(200, "POST", "/v1/auth/mfa/totp/confirm", token, `{"code":"`+used+`"}`)
	var codes []string
	for _, c := range conf["recovery_codes"].([]any) {
		codes = append(codes, c.(string))
	}
	if len(codes) != 10 {
		h.t.Fatalf("recovery codes %v", codes)
	}
	return secret, codes, used
}

func loginBody(email, password string) string {
	b, _ := json.Marshal(map[string]string{"email": email, "password": password})
	return string(b)
}

func TestLoginSessionsAndLogout(t *testing.T) {
	h := newCPHarness(t)
	email := uniqueEmail()
	user := h.passwordUser(email, "first-password-123")

	if status, out := h.do("POST", "/v1/auth/login", "", loginBody(email, "wrong-password-123")); status != 401 {
		t.Fatalf("wrong password: %d %v", status, out)
	}
	out := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "first-password-123"))
	tokenA := out["token"].(string)
	me := out["user"].(map[string]any)
	if me["id"] != user.String() || me["mfa_enabled"] != false || me["has_password"] != true || me["is_instance_admin"] != false {
		t.Errorf("user %v", me)
	}
	tokenB := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "first-password-123"))["token"].(string)

	me = h.expect(200, "GET", "/v1/auth/me", tokenA, "")
	if me["email"] != email || me["identities"] == nil {
		t.Errorf("me %v", me)
	}
	sessions := h.expect(200, "GET", "/v1/auth/sessions", tokenA, "")["items"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("sessions %v", sessions)
	}
	var other string
	for _, s := range sessions {
		row := s.(map[string]any)
		if row["current"] != true {
			other = row["id"].(string)
		}
	}
	// Revoking B from A ends B at once.
	h.expect(204, "DELETE", "/v1/auth/sessions/"+other, tokenA, "")
	if status, out := h.do("GET", "/v1/auth/me", tokenB, ""); status != 401 || out["code"] != "session_revoked" {
		t.Errorf("revoked session: %d %v", status, out)
	}
	// Another user's session cannot be revoked.
	strangerToken, _ := h.user("")
	h.expect(404, "DELETE", "/v1/auth/sessions/"+other, strangerToken, "")

	// Password change: refuses short passwords and a wrong current one, and
	// ends the other sessions.
	tokenC := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "first-password-123"))["token"].(string)
	h.expect(400, "POST", "/v1/auth/password", tokenA, `{"current_password":"first-password-123","new_password":"short"}`)
	h.expect(401, "POST", "/v1/auth/password", tokenA, `{"current_password":"nope-nope-nope","new_password":"second-password-123"}`)
	h.expect(204, "POST", "/v1/auth/password", tokenA, `{"current_password":"first-password-123","new_password":"second-password-123"}`)
	h.expect(401, "GET", "/v1/auth/me", tokenC, "")
	h.expect(200, "GET", "/v1/auth/me", tokenA, "")
	h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "second-password-123"))

	h.expect(204, "POST", "/v1/auth/logout", tokenA, "")
	h.expect(401, "GET", "/v1/auth/me", tokenA, "")

	// A disabled user cannot log in, and their sessions end (the session
	// lookup joins users; this app has not cached the new token yet).
	tokenD := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "second-password-123"))["token"].(string)
	if _, err := h.db.Exec(context.Background(), `UPDATE users SET disabled_at = NOW() WHERE id = $1`, user); err != nil {
		t.Fatal(err)
	}
	if status, out := h.do("POST", "/v1/auth/login", "", loginBody(email, "second-password-123")); status != 403 ||
		out["code"] != "account_disabled" {
		t.Errorf("disabled login: %d %v", status, out)
	}
	h.expect(401, "GET", "/v1/auth/me", tokenD, "")
}

func TestMFALoginReplayAndRecovery(t *testing.T) {
	h := newCPHarness(t)
	email := uniqueEmail()
	h.passwordUser(email, "mfa-password-1234")
	token := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "mfa-password-1234"))["token"].(string)
	secret, codes, used := h.enableMFA(token)
	// With 2FA rows in the database, the control plane refuses to start
	// without MFA_ENC_KEY.
	if err := checkMFAKey(context.Background(), h.db, nil); err == nil || !strings.Contains(err.Error(), "MFA_ENC_KEY") {
		t.Errorf("startup without MFA_ENC_KEY: %v", err)
	}
	if me := h.expect(200, "GET", "/v1/auth/me", token, ""); me["mfa_enabled"] != true {
		t.Errorf("me %v", me)
	}
	// The secret is stored encrypted.
	var sealed []byte
	if err := h.db.QueryRow(context.Background(),
		`SELECT m.totp_secret_enc FROM user_mfa m JOIN users u ON u.id = m.user_id WHERE u.email = $1`, email).
		Scan(&sealed); err != nil || strings.Contains(string(sealed), secret) {
		t.Fatalf("stored secret: %v", err)
	}

	login := func() string {
		out := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "mfa-password-1234"))
		if out["mfa_required"] != true || out["token"] != nil {
			t.Fatalf("login with 2FA: %v", out)
		}
		return out["mfa_token"].(string)
	}
	verify := func(mfaToken, code string) (int, map[string]any) {
		return h.do("POST", "/v1/auth/mfa/verify", "", `{"mfa_token":"`+mfaToken+`","code":"`+code+`"}`)
	}

	// The mfa_token is not a session token.
	mt := login()
	h.expect(401, "GET", "/v1/auth/me", mt, "")

	// The code used to confirm the setup is refused for its window (replay);
	// the exact code, since bcrypt under -race can make the confirm cross a
	// 30-second step.
	if status, out := verify(mt, used); status != 401 || out["code"] != "invalid_code" {
		t.Errorf("replayed code: %d %v", status, out)
	}
	status, out := verify(mt, totpNow(t, secret, 1))
	if status != 200 || out["token"] == nil {
		t.Fatalf("next step's code: %d %v", status, out)
	}
	// The mfa_token is single use, and the code is now spent too.
	if status, _ := verify(mt, totpNow(t, secret, 1)); status != 401 {
		t.Errorf("mfa_token reused: %d", status)
	}
	session := out["token"].(string)

	// Wrong codes: 5 attempts per mfa_token, then even a right code fails.
	mt = login()
	for i := range 5 {
		if status, _ := verify(mt, "00000"+strconv.Itoa(i)); status != 401 {
			t.Fatalf("wrong code %d: %d", i, status)
		}
	}
	if status, out := verify(mt, codes[0]); status != 401 || out["code"] != "mfa_token_invalid" {
		t.Errorf("after 5 attempts: %d %v", status, out)
	}

	// The per-IP limit (10 a minute) is reached: the IP limiter itself is the
	// login's, so carry on with a fresh app on the same database.
	_, _ = verify(mt, codes[0]) // the 10th
	if status, _ := verify(mt, codes[0]); status != 429 {
		t.Errorf("11th verify within a minute: %d, want 429", status)
	}
	h.app = newCPHarness(t).app

	// A recovery code works once.
	if status, out := verify(login(), strings.ToUpper(codes[1])); status != 200 {
		t.Fatalf("recovery code: %d %v", status, out)
	}
	if status, _ := verify(login(), codes[1]); status != 401 {
		t.Errorf("recovery code reused: %d", status)
	}

	// Regenerating needs a code and replaces the old ones.
	h.expect(401, "POST", "/v1/auth/mfa/recovery-codes/regenerate", session, `{"code":"123456"}`)
	fresh := h.expect(200, "POST", "/v1/auth/mfa/recovery-codes/regenerate", session, `{"code":"`+codes[2]+`"}`)
	if len(fresh["recovery_codes"].([]any)) != 10 {
		t.Errorf("regenerated %v", fresh)
	}
	if status, _ := verify(login(), codes[3]); status != 401 {
		t.Error("an old recovery code still works")
	}

	// Turning 2FA off needs a code.
	newCode := fresh["recovery_codes"].([]any)[0].(string)
	h.expect(401, "DELETE", "/v1/auth/mfa", session, `{"code":"999999"}`)
	h.expect(204, "DELETE", "/v1/auth/mfa", session, `{"code":"`+newCode+`"}`)
	if out := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "mfa-password-1234")); out["token"] == nil {
		t.Errorf("login after 2FA off: %v", out)
	}
}

func TestOrgRequiresMFA(t *testing.T) {
	h := newCPHarness(t)
	org, _, ownerToken := h.org(auth.RoleOwner)
	email := uniqueEmail()
	user := h.passwordUser(email, "member-password-12")
	h.addMember(org, user, auth.RoleMember)
	// A session from before the requirement.
	before := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "member-password-12"))["token"].(string)

	// The owner cannot require 2FA without having it (would lock out).
	if status, out := h.do("PUT", "/v1/organizations/"+org.String()+"/security", ownerToken,
		`{"require_mfa":true}`); status != 409 || out["code"] != "would_lock_out" {
		t.Errorf("require without own 2FA: %d %v", status, out)
	}
	h.setSecurity(org, `INSERT INTO org_security (org_id, require_mfa) VALUES ($1, true)`)

	// The old session lost the org; it is not a 2FA session.
	if status, out := h.do("GET", "/v1/organizations/"+org.String(), before, ""); status != 403 || out["code"] != "mfa_required" {
		t.Errorf("old session: %d %v", status, out)
	}

	out := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "member-password-12"))
	if out["mfa_enroll_required"] != true || out["token"] != nil {
		t.Fatalf("login: %v", out)
	}
	mt := out["mfa_token"].(string)
	// The enrollment token reaches the 2FA setup endpoints and nothing else.
	h.expect(401, "GET", "/v1/auth/me", mt, "")
	h.expect(401, "GET", "/v1/organizations", mt, "")
	setup := h.expect(200, "POST", "/v1/auth/mfa/totp/setup", mt, `{}`)
	secret := setup["secret"].(string)
	h.expect(401, "POST", "/v1/auth/mfa/totp/confirm", mt, `{"code":"000000"}`)
	conf := h.expect(200, "POST", "/v1/auth/mfa/totp/confirm", mt, `{"code":"`+totpNow(t, secret, 0)+`"}`)
	session, _ := conf["token"].(string)
	if session == "" || len(conf["recovery_codes"].([]any)) != 10 {
		t.Fatalf("confirm: %v", conf)
	}
	// The enrollment token is spent.
	h.expect(401, "POST", "/v1/auth/mfa/totp/setup", mt, `{}`)
	h.expect(200, "GET", "/v1/organizations/"+org.String(), session, "")

	// 2FA cannot be turned off while an org requires it.
	if status, out := h.do("DELETE", "/v1/auth/mfa", session, `{"code":"`+totpNow(t, secret, 1)+`"}`); status != 409 {
		t.Errorf("disable: %d %v", status, out)
	}
}

func TestLoginMethodAndLifetime(t *testing.T) {
	h := newCPHarness(t)
	org, _, token := h.org(auth.RoleAdmin)
	h.setSecurity(org, `INSERT INTO org_security (org_id, allowed_login_methods) VALUES ($1, '{google}')`)
	if status, out := h.do("GET", "/v1/organizations/"+org.String(), token, ""); status != 403 ||
		out["code"] != "login_method_not_allowed" {
		t.Errorf("method: %d %v", status, out)
	}
	h.setSecurity(org, `UPDATE org_security SET allowed_login_methods = NULL, session_lifetime_hours = 1 WHERE org_id = $1`)
	h.expect(200, "GET", "/v1/organizations/"+org.String(), token, "")
	if _, err := h.db.Exec(context.Background(),
		`UPDATE sessions SET created_at = NOW() - interval '2 hours' WHERE user_id = (SELECT user_id FROM sessions ORDER BY created_at DESC LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	// The app caches sessions for a few seconds; a fresh harness reads the row.
	h2 := &cpHarness{t: t, db: h.db, app: newCPHarness(t).app}
	if status, out := h2.do("GET", "/v1/organizations/"+org.String(), token, ""); status != 401 || out["code"] != "session_expired" {
		t.Errorf("lifetime: %d %v", status, out)
	}
	// GET security shows every method when none is restricted.
	ownerOrg, _, owner := h.org(auth.RoleOwner)
	sec := h.expect(200, "GET", "/v1/organizations/"+ownerOrg.String()+"/security", owner, "")
	// Unrestricted login methods read as null, not a list pinned to today's
	// providers.
	if sec["require_mfa"] != false || sec["session_lifetime_hours"] != float64(12) || sec["allowed_login_methods"] != nil {
		t.Errorf("security %v", sec)
	}
	h.expect(400, "PUT", "/v1/organizations/"+ownerOrg.String()+"/security", owner, `{"allowed_login_methods":[]}`)
	h.expect(400, "PUT", "/v1/organizations/"+ownerOrg.String()+"/security", owner, `{"allowed_login_methods":["oidc:nope"]}`)
	h.expect(400, "PUT", "/v1/organizations/"+ownerOrg.String()+"/security", owner, `{"session_lifetime_hours":48}`)
	h.expect(400, "PUT", "/v1/organizations/"+ownerOrg.String()+"/security", owner,
		`{"domain_join":[{"domain":"example.com","provider_id":"`+uuid.NewString()+`","role":"viewer"}]}`)
	h.expect(200, "PUT", "/v1/organizations/"+ownerOrg.String()+"/security", owner, `{"session_lifetime_hours":8}`)
	// An admin reads but does not write.
	adminTok := h.member(ownerOrg, auth.RoleAdmin)
	h.expect(200, "GET", "/v1/organizations/"+ownerOrg.String()+"/security", adminTok, "")
	h.expect(403, "PUT", "/v1/organizations/"+ownerOrg.String()+"/security", adminTok, `{}`)
}

func TestMemberManagement(t *testing.T) {
	h := newCPHarness(t)
	org, ownerID, owner := h.org(auth.RoleOwner)
	base := "/v1/organizations/" + org.String() + "/members"
	adminID := h.passwordUser(uniqueEmail(), "admin-password-12")
	h.addMember(org, adminID, auth.RoleAdmin)
	admin, _ := h.sessionToken(adminID)
	memberID := h.passwordUser(uniqueEmail(), "member-password-1")
	h.addMember(org, memberID, auth.RoleMember)

	list := h.expect(200, "GET", base+"?limit=2", admin, "")
	if list["total"] != float64(3) || len(list["items"].([]any)) != 2 || list["next_cursor"] == nil {
		t.Fatalf("members %v", list)
	}
	row := list["items"].([]any)[0].(map[string]any)
	for _, k := range []string{"user_id", "email", "display_name", "role", "mfa_enabled", "login_methods", "last_login_at", "joined_at", "disabled"} {
		if _, ok := row[k]; !ok {
			t.Errorf("member row lacks %s: %v", k, row)
		}
	}
	if got := h.expect(200, "GET", base+"?role=owner", admin, "")["items"].([]any); len(got) != 1 {
		t.Errorf("role filter %v", got)
	}
	h.expect(403, "GET", base, h.member(org, auth.RoleMember), "")

	// Last owner: cannot be demoted or removed, not even by themselves.
	if status, out := h.do("PUT", base+"/"+ownerID.String(), owner, `{"role":"admin"}`); status != 409 || out["code"] != "last_owner" {
		t.Errorf("demote last owner: %d %v", status, out)
	}
	h.expect(409, "DELETE", base+"/"+ownerID.String(), owner, "")
	// An admin cannot grant owner, nor change or remove an owner.
	h.expect(403, "PUT", base+"/"+memberID.String(), admin, `{"role":"owner"}`)
	h.expect(403, "PUT", base+"/"+ownerID.String(), admin, `{"role":"member"}`)
	h.expect(403, "DELETE", base+"/"+ownerID.String(), admin, "")
	h.expect(403, "POST", base+"/"+ownerID.String()+"/revoke-sessions", admin, "")
	// An admin manages roles below owner.
	h.expect(200, "PUT", base+"/"+memberID.String(), admin, `{"role":"viewer"}`)
	h.expect(400, "PUT", base+"/"+memberID.String(), admin, `{"role":"root"}`)
	// Someone outside the org is not a member here.
	_, stranger := h.user("")
	h.expect(404, "PUT", base+"/"+stranger.String(), owner, `{"role":"viewer"}`)
	// With a second owner, the first can step down.
	h.expect(200, "PUT", base+"/"+adminID.String(), owner, `{"role":"owner"}`)
	h.expect(200, "PUT", base+"/"+ownerID.String(), owner, `{"role":"admin"}`)
	if h.role(ownerID, org) != "admin" {
		t.Error("demotion not stored")
	}

	// Reset 2FA is owner only; revoke sessions ends the member's sessions.
	memberTok, _ := h.sessionToken(memberID)
	h.expect(403, "POST", base+"/"+memberID.String()+"/reset-mfa", owner, "") // owner is now admin
	h.expect(204, "POST", base+"/"+memberID.String()+"/reset-mfa", admin, "") // admin is now owner
	memberTok, _ = h.sessionToken(memberID)
	// An org admin is not an owner of every org of the member: refused.
	if status, out := h.do("POST", base+"/"+memberID.String()+"/revoke-sessions", owner, ""); status != 403 ||
		out["code"] != "not_sole_authority" {
		t.Errorf("revoke by admin: %d %v", status, out)
	}
	h.expect(200, "POST", base+"/"+memberID.String()+"/revoke-sessions", admin, "")
	h.expect(401, "GET", "/v1/auth/me", memberTok, "")

	// Removing a member ends their access to the org.
	memberTok, _ = h.sessionToken(memberID)
	h.expect(204, "DELETE", base+"/"+memberID.String(), admin, "")
	h.expect(403, "GET", "/v1/organizations/"+org.String(), memberTok, "")

	// The activity log has the changes, newest first, filterable.
	act := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/activity?action=member.role_changed&limit=50", admin, "")
	items := act["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("activity %v", act)
	}
	first := items[0].(map[string]any)
	if first["target"] != ownerID.String() || first["actor"].(map[string]any)["id"] != adminID.String() && first["actor"].(map[string]any)["id"] != ownerID.String() {
		t.Errorf("activity row %v", first)
	}
	if d := first["details"].(map[string]any); d["from"] != "owner" || d["to"] != "admin" {
		t.Errorf("details %v", d)
	}
	reset := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/activity?action=member.mfa_reset", admin, "")
	if len(reset["items"].([]any)) != 1 {
		t.Errorf("mfa reset not logged: %v", reset)
	}
	byActor := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/activity?actor="+adminID.String()+"&limit=200", admin, "")
	for _, it := range byActor["items"].([]any) {
		if it.(map[string]any)["actor"].(map[string]any)["id"] != adminID.String() {
			t.Errorf("actor filter: %v", it)
		}
	}
	// Another org's admin sees none of it.
	other, _, otherAdmin := h.org(auth.RoleAdmin)
	if got := h.expect(200, "GET", "/v1/organizations/"+other.String()+"/activity", otherAdmin, "")["items"].([]any); len(got) != 0 {
		t.Errorf("foreign activity visible: %v", got)
	}
}

func TestProjectMembers(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	project := h.project(org, "p1")
	base := "/v1/organizations/" + org.String() + "/projects/" + project.String() + "/members"
	user := h.passwordUser(uniqueEmail(), "pm-password-1234")
	_, stranger := h.user("")
	h.expect(400, "PUT", base+"/"+user.String(), admin, `{"role":"member"}`) // not an org member yet
	h.addMember(org, user, auth.RoleViewer)
	h.expect(400, "PUT", base+"/"+user.String(), admin, `{"role":"owner"}`)
	h.expect(200, "PUT", base+"/"+user.String(), admin, `{"role":"admin"}`)
	h.expect(400, "PUT", base+"/"+stranger.String(), admin, `{"role":"member"}`)
	list := h.expect(200, "GET", base, admin, "")["items"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["role"] != "admin" {
		t.Errorf("project members %v", list)
	}
	h.expect(204, "DELETE", base+"/"+user.String(), admin, "")
	h.expect(404, "DELETE", base+"/"+user.String(), admin, "")
	// Another org's project is not found.
	otherOrg, _, _ := h.org(auth.RoleOwner)
	otherProject := h.project(otherOrg, "p2")
	h.expect(404, "GET", "/v1/organizations/"+org.String()+"/projects/"+otherProject.String()+"/members", admin, "")
}

func (h *cpHarness) instanceAdmin() (string, uuid.UUID) {
	h.t.Helper()
	token, id := h.user("admin-password-123")
	if _, err := h.db.Exec(context.Background(), `UPDATE users SET is_instance_admin = true WHERE id = $1`, id); err != nil {
		h.t.Fatal(err)
	}
	return token, id
}

func TestInstanceUsers(t *testing.T) {
	h := newCPHarness(t)
	plain, _ := h.user("plain-password-123")
	h.expect(403, "GET", "/v1/admin/users", plain, "")
	admin, adminID := h.instanceAdmin()
	if me := h.expect(200, "GET", "/v1/auth/me", admin, ""); me["is_instance_admin"] != true {
		t.Errorf("me %v", me)
	}
	email := uniqueEmail()
	created := h.expect(201, "POST", "/v1/admin/users", admin, `{"email":"`+strings.ToUpper(email)+`","display_name":"New","password":"new-user-password-1"}`)
	id := created["id"].(string)
	if created["email"] != email {
		t.Errorf("created %v", created)
	}
	h.expect(409, "POST", "/v1/admin/users", admin, `{"email":"`+email+`"}`)
	h.expect(400, "POST", "/v1/admin/users", admin, `{"email":"x","password":"short"}`)
	list := h.expect(200, "GET", "/v1/admin/users?q="+url.QueryEscape(email), admin, "")
	if items := list["items"].([]any); len(items) != 1 || items[0].(map[string]any)["login_methods"].([]any)[0] != "password" {
		t.Errorf("list %v", list)
	}
	userTok := h.expect(200, "POST", "/v1/auth/login", "", loginBody(email, "new-user-password-1"))["token"].(string)
	h.expect(200, "PUT", "/v1/admin/users/"+id, admin, `{"disabled":true}`)
	h.expect(401, "GET", "/v1/auth/me", userTok, "")
	h.expect(403, "POST", "/v1/auth/login", "", loginBody(email, "new-user-password-1"))
	h.expect(200, "PUT", "/v1/admin/users/"+id, admin, `{"disabled":false,"is_instance_admin":true}`)
	h.expect(204, "DELETE", "/v1/admin/users/"+id, admin, "")
	var gone string
	if err := h.db.QueryRow(context.Background(), `SELECT email FROM users WHERE id = $1`, id).Scan(&gone); err != nil ||
		!strings.HasPrefix(gone, "deleted-") {
		t.Errorf("anonymized: %q %v", gone, err)
	}
	h.expect(401, "POST", "/v1/auth/login", "", loginBody(email, "new-user-password-1"))

	// The last instance administrator: checked in a transaction where the
	// other admins of this shared database are demoted, then rolled back.
	err := pgx.BeginFunc(context.Background(), h.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `UPDATE users SET is_instance_admin = false WHERE id <> $1`, adminID); err != nil {
			return err
		}
		last, err := lastInstanceAdmin(context.Background(), tx, adminID)
		if err != nil {
			return err
		}
		if !last {
			t.Error("the only instance admin is not the last")
		}
		return errRollback
	})
	if err != errRollback {
		t.Fatal(err)
	}
	// The instance activity log has the changes.
	act := h.expect(200, "GET", "/v1/admin/activity?action=user.created&limit=200", admin, "")
	found := false
	for _, it := range act["items"].([]any) {
		if it.(map[string]any)["target"] == id {
			found = true
		}
	}
	if !found {
		t.Errorf("user.created not logged")
	}
	perm := h.expect(200, "GET", "/v1/permissions", plain, "")
	if len(perm["roles"].([]any)) != 4 || len(perm["capabilities"].([]any)) == 0 {
		t.Errorf("permissions %v", perm)
	}
}

var errRollback = fmt.Errorf("rollback")

func TestPaginationCursorsStable(t *testing.T) {
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleAdmin)
	base := "/v1/organizations/" + org.String() + "/invites"
	for i := range 5 {
		h.expect(201, "POST", base, admin, `{"email":"p`+strconv.Itoa(i)+`@example.com","role":"viewer"}`)
	}
	// Without limit or cursor: the old shape.
	if legacy := h.expect(200, "GET", base, admin, ""); legacy["data"] == nil || legacy["items"] != nil {
		t.Errorf("legacy shape %v", legacy)
	}
	seen := map[string]int{}
	cursor := ""
	for page := 0; page < 10; page++ {
		path := base + "?limit=2"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		out := h.expect(200, "GET", path, admin, "")
		if out["total"] == nil {
			t.Errorf("no total: %v", out)
		}
		for _, it := range out["items"].([]any) {
			seen[it.(map[string]any)["email"].(string)]++
		}
		// An insert between pages does not shift the next one.
		h.expect(201, "POST", base, admin, `{"email":"new`+strconv.Itoa(page)+`@example.com","role":"viewer"}`)
		next, _ := out["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	for i := range 5 {
		if n := seen["p"+strconv.Itoa(i)+"@example.com"]; n != 1 {
			t.Errorf("p%d seen %d times (%v)", i, n, seen)
		}
	}
	h.expect(400, "GET", base+"?limit=0", admin, "")
	h.expect(400, "GET", base+"?cursor=garbage", admin, "")
	if out := h.expect(200, "GET", base+"?limit=1000", admin, ""); len(out["items"].([]any)) > maxPageLimit {
		t.Error("limit not capped")
	}
	// The other list endpoints answer with the envelope too.
	for _, p := range []string{"api-keys", "projects", "upstreams", "policies", "requests", "exemplars", "members", "activity"} {
		out := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/"+p+"?limit=5", admin, "")
		if _, ok := out["items"]; !ok {
			t.Errorf("%s: %v", p, out)
		}
		if _, ok := out["next_cursor"]; !ok {
			t.Errorf("%s: no next_cursor", p)
		}
	}
	if out := h.expect(200, "GET", "/v1/organizations?limit=5", admin, ""); out["items"] == nil {
		t.Errorf("orgs %v", out)
	}
}

// ── OIDC ─────────────────────────────────────────────────────────────────────

// fakeIDP is an OpenID provider: discovery and keys from oidctest, and a token
// endpoint that checks PKCE and returns the ID token registered for a code.
type fakeIDP struct {
	*httptest.Server
	key  *rsa.PrivateKey
	mu   sync.Mutex
	code map[string]fakeGrant
}

type fakeGrant struct {
	challenge string
	claims    map[string]any
}

func newFakeIDP(t *testing.T) *fakeIDP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{key: key, code: map[string]fakeGrant{}}
	disc := &oidctest.Server{PublicKeys: []oidctest.PublicKey{{PublicKey: key.Public(), KeyID: "k1", Algorithm: oidc.RS256}}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			disc.ServeHTTP(w, r)
			return
		}
		_ = r.ParseForm()
		f.mu.Lock()
		g, ok := f.code[r.Form.Get("code")]
		delete(f.code, r.Form.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		raw, _ := json.Marshal(g.claims)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer",
			"id_token": oidctest.SignIDToken(key, "k1", oidc.RS256, string(raw))})
	}))
	disc.SetIssuer(f.URL)
	t.Cleanup(f.Close)
	return f
}

// grant registers what the token endpoint returns for code.
func (f *fakeIDP) grant(code, challenge string, claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.code[code] = fakeGrant{challenge: challenge, claims: claims}
}

type ssoRun struct {
	state, nonce, challenge string
	cookie                  string // the browser binding cookie start set
}

// start begins an SSO login and returns what the provider was sent.
func (h *cpHarness) ssoStart(provider string, redirect string) ssoRun {
	h.t.Helper()
	resp := h.req("GET", "/v1/auth/oidc/"+provider+"/start?redirect="+url.QueryEscape(redirect), "", "")
	if resp.StatusCode != 302 {
		body, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("start: %d %s", resp.StatusCode, body)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" ||
		q.Get("redirect_uri") != "http://cp.test/v1/auth/oidc/"+provider+"/callback" {
		h.t.Fatalf("authorize url %s", u)
	}
	run := ssoRun{state: q.Get("state"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	for _, ck := range resp.Cookies() {
		if ck.Name == ssoCookie {
			run.cookie = ck.Value
			if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/v1/auth/oidc" {
				h.t.Errorf("binding cookie attributes: %+v", ck)
			}
		}
	}
	if run.cookie == "" {
		h.t.Fatal("start set no binding cookie")
	}
	return run
}

// ssoCallback runs the callback in the browser that started run and returns
// the query of the UI page it redirects to.
func (h *cpHarness) ssoCallback(provider string, run ssoRun, code string) url.Values {
	h.t.Helper()
	_, v := h.ssoCallbackAt(provider, run.state, code, run.cookie)
	return v
}

// ssoCallbackAt runs the callback with a given binding cookie ("" for none)
// and returns the UI path and its query.
func (h *cpHarness) ssoCallbackAt(provider, state, code, cookie string) (string, url.Values) {
	h.t.Helper()
	r := httptest.NewRequest("GET", "/v1/auth/oidc/"+provider+"/callback?state="+url.QueryEscape(state)+
		"&code="+url.QueryEscape(code), nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: ssoCookie, Value: cookie})
	}
	resp, err := h.app.Test(r, -1)
	if err != nil {
		h.t.Fatal(err)
	}
	loc := resp.Header.Get("Location")
	path, query, ok := strings.Cut(loc, "?")
	if resp.StatusCode != 302 || !ok || !strings.HasPrefix(path, "/ui/") {
		h.t.Fatalf("callback: %d %q", resp.StatusCode, loc)
	}
	v, _ := url.ParseQuery(query)
	return path, v
}

func TestOIDCLogin(t *testing.T) {
	idp := newFakeIDP(t)
	t.Setenv("OIDC_SECRET_TEST", "client-secret-for-tests")
	h := newCPHarness(t, func(s *appSettings) { s.publicURL = "http://cp.test" })
	admin, _ := h.instanceAdmin()
	domain := "corp-" + uuid.NewString()[:8] + ".example"

	h.expect(400, "POST", "/v1/admin/identity-providers", admin,
		`{"type":"oidc","display_name":"X","issuer":"`+idp.URL+`","client_id":"c","client_secret_env":"JWT_SECRET"}`)
	prov := h.expect(201, "POST", "/v1/admin/identity-providers", admin,
		`{"type":"oidc","display_name":"Corp SSO","issuer":"`+idp.URL+`","client_id":"guard-spec","client_secret_env":"OIDC_SECRET_TEST",
		  "allowed_domains":["`+domain+`"],"auto_provision":true}`)
	pid := prov["id"].(string)
	if _, leaked := prov["client_secret"]; leaked {
		t.Error("secret returned")
	}
	plain, _ := h.user("")
	h.expect(403, "POST", "/v1/admin/identity-providers", plain, `{}`)
	var listed bool
	status, raw := h.raw("GET", "/v1/auth/providers", "", "", "")
	listed = status == 200 && strings.Contains(raw, pid) && !strings.Contains(raw, "OIDC_SECRET")
	if !listed {
		t.Errorf("public providers: %d %s", status, raw)
	}

	// An org whose domain_join adds SSO users of the domain.
	org, _, owner := h.org(auth.RoleOwner)
	h.expect(200, "PUT", "/v1/organizations/"+org.String()+"/security", owner,
		`{"domain_join":[{"domain":"`+domain+`","provider_id":"`+pid+`","role":"viewer"}]}`)

	claims := func(nonce, sub, email string) map[string]any {
		return map[string]any{"iss": idp.URL, "aud": "guard-spec", "sub": sub, "email": email, "email_verified": true,
			"nonce": nonce, "name": "Sam", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	}

	// Happy path: a new user is provisioned and joins the org.
	email := "sam-" + uuid.NewString()[:6] + "@" + domain
	run := h.ssoStart(pid, "/ui/#/policies")
	idp.grant("code1", run.challenge, claims(run.nonce, "sub-sam", email))
	cb := h.ssoCallback(pid, run, "code1")
	if cb.Get("code") == "" || cb.Get("error") != "" {
		t.Fatalf("callback %v", cb)
	}
	out := h.expect(200, "POST", "/v1/auth/oidc/exchange", "", `{"code":"`+cb.Get("code")+`"}`)
	session := out["token"].(string)
	if out["redirect"] != "/ui/#/policies" || out["user"].(map[string]any)["has_password"] != false {
		t.Errorf("exchange %v", out)
	}
	// The code is single use.
	h.expect(401, "POST", "/v1/auth/oidc/exchange", "", `{"code":"`+cb.Get("code")+`"}`)
	h.expect(200, "GET", "/v1/organizations/"+org.String(), session, "")
	me := h.expect(200, "GET", "/v1/auth/me", session, "")
	if ids := me["identities"].([]any); len(ids) != 1 || ids[0].(map[string]any)["provider"] != "oidc" {
		t.Errorf("identities %v", me)
	}
	// The state is single use too.
	if cb := h.ssoCallback(pid, run, "code1"); cb.Get("error") != "invalid_state" {
		t.Errorf("reused state: %v", cb)
	}

	// The second login matches on (provider, subject), whatever the email.
	run = h.ssoStart(pid, "/ui/")
	idp.grant("code2", run.challenge, claims(run.nonce, "sub-sam", "renamed-"+email))
	if cb := h.ssoCallback(pid, run, "code2"); cb.Get("code") == "" {
		t.Errorf("second login %v", cb)
	}

	// State mismatch.
	if _, cb := h.ssoCallbackAt(pid, "forged-state", "code3", run.cookie); cb.Get("error") != "invalid_state" {
		t.Errorf("forged state %v", cb)
	}
	// Login CSRF: a callback in a browser that did not start the login (no
	// binding cookie, or another one) is refused, and spends the state.
	run = h.ssoStart(pid, "/ui/")
	idp.grant("code3b", run.challenge, claims(run.nonce, "sub-sam", email))
	if _, cb := h.ssoCallbackAt(pid, run.state, "code3b", ""); cb.Get("error") != "invalid_state" {
		t.Errorf("no binding cookie %v", cb)
	}
	other := h.ssoStart(pid, "/ui/")
	idp.grant("code3c", other.challenge, claims(other.nonce, "sub-sam", email))
	if _, cb := h.ssoCallbackAt(pid, other.state, "code3c", run.cookie); cb.Get("error") != "invalid_state" {
		t.Errorf("another browser's cookie %v", cb)
	}
	// Nonce mismatch.
	run = h.ssoStart(pid, "/ui/")
	idp.grant("code4", run.challenge, claims("other-nonce", "sub-x", "x@"+domain))
	if cb := h.ssoCallback(pid, run, "code4"); cb.Get("error") != "invalid_nonce" {
		t.Errorf("nonce %v", cb)
	}
	// PKCE mismatch: the provider expects another challenge.
	run = h.ssoStart(pid, "/ui/")
	idp.grant("code5", "not-the-challenge", claims(run.nonce, "sub-y", "y@"+domain))
	if cb := h.ssoCallback(pid, run, "code5"); cb.Get("error") != "exchange_failed" {
		t.Errorf("pkce %v", cb)
	}
	// Domain not allowed.
	run = h.ssoStart(pid, "/ui/")
	idp.grant("code6", run.challenge, claims(run.nonce, "sub-z", "z@elsewhere.example"))
	if cb := h.ssoCallback(pid, run, "code6"); cb.Get("error") != "domain_not_allowed" {
		t.Errorf("domain %v", cb)
	}
	// Unverified email.
	run = h.ssoStart(pid, "/ui/")
	c := claims(run.nonce, "sub-u", "u@"+domain)
	c["email_verified"] = false
	idp.grant("code7", run.challenge, c)
	if cb := h.ssoCallback(pid, run, "code7"); cb.Get("error") != "email_not_verified" {
		t.Errorf("unverified %v", cb)
	}
	// Email collision with a password account: refused (no takeover).
	victim := "victim-" + uuid.NewString()[:6] + "@" + domain
	victimID := h.passwordUser(victim, "victim-password-12")
	run = h.ssoStart(pid, "/ui/")
	idp.grant("code8", run.challenge, claims(run.nonce, "sub-attacker", victim))
	if cb := h.ssoCallback(pid, run, "code8"); cb.Get("error") != "account_exists" {
		t.Errorf("collision %v", cb)
	}
	// The victim can link the identity from their profile instead: the
	// callback hands the UI a one-time code, which only the user who started
	// the link can complete.
	victimTok, _ := h.sessionToken(victimID)
	linkStart := func(token string) url.Values {
		link := h.expect(200, "POST", "/v1/auth/identities/"+pid+"/link/start", token, "")
		lu, _ := url.Parse(link["url"].(string))
		return lu.Query()
	}
	lq := linkStart(victimTok)
	idp.grant("code9", lq.Get("code_challenge"), claims(lq.Get("nonce"), "sub-victim", victim))
	path, cb := h.ssoCallbackAt(pid, lq.Get("state"), "code9", "")
	if path != "/ui/account" || cb.Get("link_code") == "" {
		t.Fatalf("link callback %s %v", path, cb)
	}
	if me := h.expect(200, "GET", "/v1/auth/me", victimTok, ""); len(me["identities"].([]any)) != 0 {
		t.Error("linked before completion")
	}
	if status, out := h.do("POST", "/v1/auth/identities/link/complete", session, `{"code":"`+cb.Get("link_code")+`"}`); status != 409 ||
		out["code"] != "link_wrong_user" {
		t.Errorf("another user's link: %d %v", status, out)
	}
	done := h.expect(200, "POST", "/v1/auth/identities/link/complete", victimTok, `{"code":"`+cb.Get("link_code")+`"}`)
	if done["provider_id"] != pid || done["display_name"] != "Corp SSO" || done["email"] != victim {
		t.Errorf("link complete %v", done)
	}
	if status, out := h.do("POST", "/v1/auth/identities/link/complete", victimTok, `{"code":"`+cb.Get("link_code")+`"}`); status != 400 ||
		out["code"] != "link_expired" {
		t.Errorf("reused link code: %d %v", status, out)
	}
	if me := h.expect(200, "GET", "/v1/auth/me", victimTok, ""); len(me["identities"].([]any)) != 1 {
		t.Errorf("not linked: %v", me)
	}
	// A manual link grants no org through domain_join.
	if h.role(victimID, org) != "" {
		t.Error("a manual link ran domain_join")
	}

	// Link CSRF: an attacker starts a link and sends the provider's URL to a
	// victim. The victim's identity lands in a code bound to the attacker's
	// account, in the victim's browser; the victim's UI cannot complete it,
	// and the attacker never sees the code.
	attackerTok, attackerID := h.user("attacker-password-1")
	lq = linkStart(attackerTok)
	target := "target-" + uuid.NewString()[:6] + "@" + domain
	idp.grant("code9b", lq.Get("code_challenge"), claims(lq.Get("nonce"), "sub-target", target))
	_, cb = h.ssoCallbackAt(pid, lq.Get("state"), "code9b", "")
	targetTok, _ := h.user("target-password-12")
	h.expect(409, "POST", "/v1/auth/identities/link/complete", targetTok, `{"code":"`+cb.Get("link_code")+`"}`)
	// A link that fails at the provider reports to the account page.
	lq = linkStart(attackerTok)
	idp.grant("code9c", lq.Get("code_challenge"), claims(lq.Get("nonce"), "sub-x", "x@elsewhere.example"))
	if path, cb := h.ssoCallbackAt(pid, lq.Get("state"), "code9c", ""); path != "/ui/account" || cb.Get("link_error") != "domain_not_allowed" {
		t.Errorf("link error: %s %v", path, cb)
	}
	var linked int
	if err := h.db.QueryRow(context.Background(), `SELECT count(*) FROM user_identities WHERE user_id = $1`, attackerID).
		Scan(&linked); err != nil || linked != 0 {
		t.Errorf("attacker linked: %d %v", linked, err)
	}
	// Unlinking keeps the password, so it is allowed; an SSO-only user cannot
	// unlink their only identity.
	h.expect(204, "DELETE", "/v1/auth/identities/"+pid, victimTok, "")
	if status, out := h.do("DELETE", "/v1/auth/identities/"+pid, session, ""); status != 409 || out["code"] != "last_login_method" {
		t.Errorf("unlink last: %d %v", status, out)
	}
	// An SSO-only account has no password to change.
	h.expect(409, "POST", "/v1/auth/password", session, `{"current_password":"","new_password":"some-password-123"}`)

	// No auto-provision: unknown users are refused.
	h.expect(200, "PUT", "/v1/admin/identity-providers/"+pid, admin, `{"auto_provision":false}`)
	run = h.ssoStart(pid, "/ui/")
	idp.grant("code10", run.challenge, claims(run.nonce, "sub-new", "new@"+domain))
	if cb := h.ssoCallback(pid, run, "code10"); cb.Get("error") != "not_provisioned" {
		t.Errorf("auto_provision off %v", cb)
	}
	// Redirects outside /ui/ are refused.
	for _, bad := range []string{"https://evil.example/", "//evil.example/ui/", "/ui/..//x", "/api"} {
		if resp := h.req("GET", "/v1/auth/oidc/"+pid+"/start?redirect="+url.QueryEscape(bad), "", ""); resp.StatusCode != 400 {
			t.Errorf("redirect %q: %d", bad, resp.StatusCode)
		}
	}
	// A login method the org excludes: the SSO session loses the org.
	h.setSecurity(org, `UPDATE org_security SET allowed_login_methods = '{password}' WHERE org_id = $1`)
	if status, out := h.do("GET", "/v1/organizations/"+org.String(), session, ""); status != 403 || out["code"] != "login_method_not_allowed" {
		t.Errorf("method %d %v", status, out)
	}
	// A disabled provider is not offered and cannot start.
	h.expect(200, "PUT", "/v1/admin/identity-providers/"+pid, admin, `{"enabled":false}`)
	if resp := h.req("GET", "/v1/auth/oidc/"+pid+"/start", "", ""); resp.StatusCode != 404 {
		t.Errorf("disabled start: %d", resp.StatusCode)
	}
	// Deleting it would strand the SSO-only user.
	h.expect(409, "DELETE", "/v1/admin/identity-providers/"+pid, admin, "")
	h.expect(204, "DELETE", "/v1/admin/identity-providers/"+pid+"?force=true", admin, "")
}

func TestGoogleHostedDomain(t *testing.T) {
	p := providerRow{Type: "google", AllowedDomains: []string{"acme.com"}}
	if domainAllowed(p, "a@acme.com", "") {
		t.Error("google without hd accepted")
	}
	if domainAllowed(p, "a@acme.com", "other.com") || domainAllowed(p, "a@other.com", "acme.com") {
		t.Error("wrong domain accepted")
	}
	if !domainAllowed(p, "a@acme.com", "acme.com") {
		t.Error("right domain refused")
	}
	if !domainAllowed(providerRow{Type: "google"}, "a@gmail.com", "") {
		t.Error("no allowlist should accept any verified email")
	}
}

// ── Model providers ──────────────────────────────────────────────────────────

func TestUpstreamProviderFieldsAndTest(t *testing.T) {
	models := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer test-upstream-key" ||
			r.Header.Get("OpenAI-Organization") != "org_x" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"secret detail"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"}]}`))
	}))
	defer models.Close()
	env := map[string]string{"UPSTREAM_KEY_SAFE": "test-upstream-key", "UPSTREAM_KEY_EXPL": "test-upstream-key"}
	t.Setenv("GUARD_ENV", "")
	h := newCPHarness(t)
	org, _, admin := h.org(auth.RoleOwner) // the connection test is owner only
	// UPSTREAM_KEY_EXPL lists this org by id; UPSTREAM_KEY_SAFE is for every org.
	h.app = newCPHarness(t, withKeyOrgs(config.MustParseKeyOrgs("UPSTREAM_KEY_SAFE=*;UPSTREAM_KEY_EXPL="+org.String())),
		func(s *appSettings) { s.allowPrivate = true; s.getenv = func(k string) string { return env[k] } }).app
	base := "/v1/organizations/" + org.String() + "/upstreams"

	h.expect(400, "POST", base, admin, `{"name":"bad","base_url":"`+models.URL+`/v1","headers":{"X-Org":"sk-live-123"}}`)
	h.expect(400, "POST", base, admin, `{"name":"bad","base_url":"`+models.URL+`/v1","headers":{"Authorization":"x"}}`)
	h.expect(400, "POST", base, admin, `{"name":"bad","base_url":"`+models.URL+`/v1","provider":"nope"}`)
	h.expect(400, "POST", base, admin, `{"name":"bad","base_url":"`+models.URL+`/v1","models":["a"],"default_model":"b"}`)
	h.expect(400, "POST", base, admin, `{"name":"bad","base_url":"`+models.URL+`/v1","api_version":"2024-10-21"}`)
	h.expect(400, "POST", base, admin, `{"name":"bad","base_url":"`+models.URL+`/v1","model":"a","default_model":"b"}`)
	up := h.expect(201, "POST", base, admin, `{"name":"gpt","base_url":"`+models.URL+`/v1","provider":"openai",
		"display_name":"GPT-4o (prod)","models":["gpt-4o","gpt-4o-mini"],"default_model":"gpt-4o","api_key_env":"UPSTREAM_KEY_EXPL",
		"headers":{"OpenAI-Organization":"org_x"},"max_tokens_cap":4096,"retries":1,"tags":["prod"],"timeout_ms":60000}`)
	if up["model"] != "gpt-4o" || up["default_model"] != "gpt-4o" || up["provider"] != "openai" ||
		up["max_tokens_cap"] != float64(4096) || len(up["models"].([]any)) != 2 {
		t.Errorf("created %v", up)
	}
	id := up["id"].(string)
	res := h.expect(200, "POST", base+"/"+id+"/test", admin, "")
	if res["ok"] != true || res["status"] != float64(200) || len(res["models_found"].([]any)) != 2 || res["key_sent"] != true {
		t.Errorf("test %v", res)
	}
	// A key every org may use ("*") is not sent to an address an org owner
	// chose, outside GUARD_ENV=dev.
	wild := h.expect(201, "POST", base, admin, `{"name":"wild","base_url":"`+models.URL+`/v1","api_key_env":"UPSTREAM_KEY_SAFE",
		"headers":{"OpenAI-Organization":"org_x"}}`)
	res = h.expect(200, "POST", base+"/"+wild["id"].(string)+"/test", admin, "")
	if res["key_sent"] != false || res["status"] != float64(401) || !strings.Contains(fmt.Sprint(res["note"]), "not sent") {
		t.Errorf("wildcard key: %v", res)
	}
	t.Setenv("GUARD_ENV", "dev")
	if res = h.expect(200, "POST", base+"/"+wild["id"].(string)+"/test", admin, ""); res["key_sent"] != true || res["ok"] != true {
		t.Errorf("wildcard key in dev: %v", res)
	}
	t.Setenv("GUARD_ENV", "")
	// Admins cannot test (owner only).
	h.expect(403, "POST", base+"/"+id+"/test", h.member(org, auth.RoleAdmin), "")
	upd := h.expect(200, "PUT", base+"/"+id, admin, `{"default_model":"gpt-4o-mini","max_tokens_cap":null,"tags":[]}`)
	if upd["model"] != "gpt-4o-mini" || upd["max_tokens_cap"] != nil {
		t.Errorf("updated %v", upd)
	}
	// A failing upstream: the answer never carries its body.
	h.expect(200, "PUT", base+"/"+id, admin, `{"headers":{}}`)
	res = h.expect(200, "POST", base+"/"+id+"/test", admin, "")
	if res["ok"] != false || res["status"] != float64(401) || strings.Contains(fmt.Sprint(res), "secret detail") {
		t.Errorf("failing test %v", res)
	}
	// Members cannot test.
	h.expect(403, "POST", base+"/"+id+"/test", h.member(org, auth.RoleMember), "")
	if cat := h.expect(200, "GET", "/v1/providers/catalog", admin, ""); len(cat["items"].([]any)) != 7 {
		t.Errorf("catalog %v", cat)
	}
}

func TestUpstreamTestSSRF(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"internal-model"}]}`))
	}))
	defer local.Close()
	// UPSTREAM_ALLOW_PRIVATE is off: a loopback upstream is refused at dial time.
	h := newCPHarness(t, func(s *appSettings) { s.getenv = func(string) string { return "" } })
	org, _, admin := h.org(auth.RoleOwner)
	base := "/v1/organizations/" + org.String() + "/upstreams"
	up := h.expect(201, "POST", base, admin, `{"name":"local","base_url":"`+local.URL+`/v1"}`)
	res := h.expect(200, "POST", base+"/"+up["id"].(string)+"/test", admin, "")
	if res["ok"] != false || !strings.Contains(res["error"].(string), "not allowed") || len(res["models_found"].([]any)) != 0 {
		t.Errorf("private upstream: %v", res)
	}
	// Metadata addresses are refused when saved.
	h.expect(400, "POST", base, admin, `{"name":"meta","base_url":"http://169.254.169.254/v1"}`)
	// A key the org may not use is refused by the test as by the gateway.
	h2 := newCPHarness(t, func(s *appSettings) { s.allowPrivate = true })
	org2, _, admin2 := h2.org(auth.RoleOwner)
	if _, err := h2.db.Exec(context.Background(), `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	err := tenant.WithOrg(context.Background(), h2.db, org2, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO upstreams (org_id, name, base_url, api_key_env) VALUES ($1, 'acme', $2, 'UPSTREAM_KEY_ACME')`,
			org2, local.URL+"/v1")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	list := h2.expect(200, "GET", "/v1/organizations/"+org2.String()+"/upstreams?limit=5", admin2, "")
	acme := list["items"].([]any)[0].(map[string]any)["id"].(string)
	res = h2.expect(200, "POST", "/v1/organizations/"+org2.String()+"/upstreams/"+acme+"/test", admin2, "")
	if res["ok"] != false || !strings.Contains(res["error"].(string), "UPSTREAM_KEY_ORGS") {
		t.Errorf("key allowlist: %v", res)
	}
}
