//go:build integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/promptshield/promptshield/internal/auth"
	"github.com/promptshield/promptshield/internal/policy"
	"github.com/promptshield/promptshield/internal/tenant"
)

var testSecret = []byte("integration-test-secret-0123456789abcdef")

type cpHarness struct {
	t   *testing.T
	db  *pgxpool.Pool
	app *fiber.App
}

func newCPHarness(t *testing.T) *cpHarness {
	t.Helper()
	ctx := context.Background()
	db, err := pgxpool.New(ctx, envOr("TEST_DATABASE_URL", "postgres://ps_app:ps_app@localhost:5432/promptshield?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	eng, err := policy.New()
	if err != nil {
		t.Fatal(err)
	}
	return &cpHarness{t: t, db: db, app: newApp(db, testSecret, eng, "")}
}

// org creates an org and a user with role in it, and returns both and a token.
func (h *cpHarness) org(role auth.Role) (orgID, userID uuid.UUID, token string) {
	h.t.Helper()
	ctx := context.Background()
	orgID = uuid.New()
	hash, err := auth.HashPassword("existing-password-123")
	if err != nil {
		h.t.Fatal(err)
	}
	err = tenant.WithOrg(ctx, h.db, orgID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1,'o',$2)`, orgID, orgID.String()); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO users (email, hashed_password) VALUES ($1,$2) RETURNING id`,
			uuid.NewString()+"@example.com", hash).Scan(&userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1,$2,$3::org_role)`,
			userID, orgID, string(role))
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	token, err = auth.IssueToken(testSecret, userID)
	if err != nil {
		h.t.Fatal(err)
	}
	return orgID, userID, token
}

func (h *cpHarness) do(method, path, token, body string) (int, map[string]any) {
	h.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.app.Test(req, -1)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return resp.StatusCode, out
}

func (h *cpHarness) role(user, org uuid.UUID) string {
	h.t.Helper()
	var role string
	err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT role::text FROM org_memberships WHERE user_id = $1 AND org_id = $2`, user, org).Scan(&role)
	})
	if err != nil && err != pgx.ErrNoRows {
		h.t.Fatal(err)
	}
	return role
}

func TestInvites(t *testing.T) {
	h := newCPHarness(t)
	orgA, _, adminA := h.org(auth.RoleAdmin)
	orgB, userB, adminB := h.org(auth.RoleAdmin)
	email := strings.ToLower(uuid.NewString()) + "@example.com"

	// An admin cannot hand out owner.
	if code, _ := h.do("POST", "/v1/orgs/"+orgA.String()+"/invites", adminA,
		`{"email":"`+email+`","role":"owner"}`); code != http.StatusForbidden {
		t.Errorf("admin inviting an owner: %d, want 403", code)
	}
	code, inv := h.do("POST", "/v1/orgs/"+orgA.String()+"/invites", adminA, `{"email":"`+email+`","role":"member"}`)
	if code != http.StatusCreated {
		t.Fatalf("create invite: %d %v", code, inv)
	}
	token, _ := inv["token"].(string)
	inviteA, _ := inv["id"].(string)
	if !strings.HasPrefix(token, invitePrefix) {
		t.Fatalf("token = %q", token)
	}

	// Only the hash is stored.
	var stored string
	err := tenant.WithOrg(context.Background(), h.db, orgA, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT token_hash FROM invites WHERE id = $1`, inviteA).Scan(&stored)
	})
	if err != nil || stored != tenant.HashKey(token) || strings.Contains(stored, token) {
		t.Errorf("stored token_hash = %q, %v", stored, err)
	}

	// Cross-org isolation: B's admin can neither see nor revoke A's invite.
	if code, _ := h.do("GET", "/v1/organizations/"+orgA.String()+"/invites", adminB, ""); code != http.StatusForbidden {
		t.Errorf("B listing A's invites: %d, want 403", code)
	}
	code, list := h.do("GET", "/v1/organizations/"+orgB.String()+"/invites", adminB, "")
	if code != http.StatusOK || len(list["data"].([]any)) != 0 {
		t.Errorf("B's own list: %d %v, want empty", code, list)
	}
	if code, _ := h.do("DELETE", "/v1/organizations/"+orgB.String()+"/invites/"+inviteA, adminB, ""); code != http.StatusNotFound {
		t.Errorf("B revoking A's invite through its own org: %d, want 404", code)
	}
	if code, _ := h.do("DELETE", "/v1/organizations/"+orgA.String()+"/invites/"+inviteA, adminB, ""); code != http.StatusForbidden {
		t.Errorf("B revoking A's invite: %d, want 403", code)
	}

	// Accepting.
	if code, _ := h.do("POST", "/v1/invites/accept", "", `{"token":"`+token+`","password":"short"}`); code != http.StatusBadRequest {
		t.Errorf("short password: %d, want 400", code)
	}
	if code, _ := h.do("POST", "/v1/invites/accept", "", `{"token":"psinv_nope","password":"long-enough-password"}`); code != http.StatusNotFound {
		t.Errorf("unknown token: %d, want 404", code)
	}
	code, acc := h.do("POST", "/v1/invites/accept", "", `{"token":"`+token+`","password":"long-enough-password"}`)
	if code != http.StatusCreated || acc["org_id"] != orgA.String() || acc["role"] != "member" || acc["token"] == "" {
		t.Fatalf("accept: %d %v", code, acc)
	}
	newUser := uuid.MustParse(acc["user_id"].(string))
	if r := h.role(newUser, orgA); r != "member" {
		t.Errorf("role in A = %q, want member", r)
	}
	if r := h.role(newUser, orgB); r != "" {
		t.Errorf("role in B = %q, want none", r)
	}
	// One-time.
	if code, _ := h.do("POST", "/v1/invites/accept", "", `{"token":"`+token+`","password":"long-enough-password"}`); code != http.StatusNotFound {
		t.Errorf("reused token: %d, want 404", code)
	}
	// The new member can log in, and cannot invite.
	if code, _ := h.do("POST", "/v1/auth/login", "", `{"email":"`+email+`","password":"long-enough-password"}`); code != http.StatusOK {
		t.Errorf("login: %d", code)
	}
	if code, _ := h.do("POST", "/v1/organizations/"+orgA.String()+"/invites", acc["token"].(string),
		`{"email":"x@example.com"}`); code != http.StatusForbidden {
		t.Errorf("member inviting: %d, want 403", code)
	}

	// Revoked and expired invites cannot be accepted.
	_, inv2 := h.do("POST", "/v1/organizations/"+orgA.String()+"/invites", adminA, `{"email":"r@example.com","role":"viewer"}`)
	if code, _ := h.do("DELETE", "/v1/organizations/"+orgA.String()+"/invites/"+inv2["id"].(string), adminA, ""); code != http.StatusNoContent {
		t.Errorf("revoke: %d", code)
	}
	if code, _ := h.do("POST", "/v1/invites/accept", "", `{"token":"`+inv2["token"].(string)+`","password":"long-enough-password"}`); code != http.StatusNotFound {
		t.Errorf("revoked invite accepted: %d", code)
	}
	_, inv3 := h.do("POST", "/v1/organizations/"+orgA.String()+"/invites", adminA, `{"email":"e@example.com","ttl_hours":1}`)
	err = tenant.WithOrg(context.Background(), h.db, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE invites SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, inv3["id"])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := h.do("POST", "/v1/invites/accept", "", `{"token":"`+inv3["token"].(string)+`","password":"long-enough-password"}`); code != http.StatusNotFound {
		t.Errorf("expired invite accepted: %d", code)
	}

	code, list = h.do("GET", "/v1/organizations/"+orgA.String()+"/invites", adminA, "")
	statuses := map[string]string{}
	for _, item := range list["data"].([]any) {
		m := item.(map[string]any)
		statuses[m["id"].(string)] = m["status"].(string)
		if _, leaked := m["token"]; leaked {
			t.Error("list returns tokens")
		}
	}
	if code != http.StatusOK || statuses[inviteA] != "accepted" || statuses[inv2["id"].(string)] != "revoked" ||
		statuses[inv3["id"].(string)] != "expired" || len(statuses) != 3 {
		t.Errorf("statuses = %v", statuses)
	}

	// An existing user joins another org with their own password.
	var emailB string
	if err := h.db.QueryRow(context.Background(), `SELECT email FROM users WHERE id = $1`, userB).Scan(&emailB); err != nil {
		t.Fatal(err)
	}
	_, inv4 := h.do("POST", "/v1/organizations/"+orgA.String()+"/invites", adminA, `{"email":"`+emailB+`","role":"viewer"}`)
	if code, _ := h.do("POST", "/v1/invites/accept", "", `{"token":"`+inv4["token"].(string)+`","password":"not-the-password"}`); code != http.StatusUnauthorized {
		t.Errorf("existing user, wrong password: %d, want 401", code)
	}
	if code, acc := h.do("POST", "/v1/invites/accept", "", `{"token":"`+inv4["token"].(string)+`","password":"existing-password-123"}`); code != http.StatusCreated {
		t.Errorf("existing user: %d %v", code, acc)
	}
	if r := h.role(userB, orgA); r != "viewer" {
		t.Errorf("B's user in A = %q, want viewer", r)
	}
	if r := h.role(userB, orgB); r != "admin" {
		t.Errorf("B's user in B = %q, want admin unchanged", r)
	}
}

func TestProjectScopedPoliciesAndKeyLimits(t *testing.T) {
	h := newCPHarness(t)
	orgA, _, adminA := h.org(auth.RoleOwner)
	orgB, _, adminB := h.org(auth.RoleOwner)

	code, proj := h.do("POST", "/v1/organizations/"+orgA.String()+"/projects", adminA, `{"name":"Support bot","slug":"support"}`)
	if code != http.StatusCreated {
		t.Fatalf("create project: %d %v", code, proj)
	}
	projA := proj["id"].(string)
	_, projB := h.do("POST", "/v1/organizations/"+orgB.String()+"/projects", adminB, `{"name":"x","slug":"x"}`)

	rules := `[{"name":"r","action":"block","condition":{"field":"injection.score","operator":">=","value":0.7}}]`
	code, pol := h.do("POST", "/v1/organizations/"+orgA.String()+"/policies", adminA,
		`{"name":"p","project_id":"`+projA+`","rules":`+rules+`}`)
	if code != http.StatusCreated {
		t.Fatalf("project policy: %d %v", code, pol)
	}
	// Another org's project is refused, even though the foreign key would accept it.
	if code, _ := h.do("POST", "/v1/organizations/"+orgA.String()+"/policies", adminA,
		`{"name":"p","project_id":"`+projB["id"].(string)+`","rules":`+rules+`}`); code != http.StatusBadRequest {
		t.Errorf("foreign project: %d, want 400", code)
	}
	_, list := h.do("GET", "/v1/organizations/"+orgA.String()+"/policies", adminA, "")
	if got := list["data"].([]any)[0].(map[string]any)["project_id"]; got != projA {
		t.Errorf("listed project_id = %v", got)
	}
	// Back to org-wide.
	if code, _ := h.do("PUT", "/v1/organizations/"+orgA.String()+"/policies/"+pol["id"].(string), adminA,
		`{"project_id":null}`); code != http.StatusOK {
		t.Errorf("clear project: %d", code)
	}
	_, list = h.do("GET", "/v1/organizations/"+orgA.String()+"/policies", adminA, "")
	if got := list["data"].([]any)[0].(map[string]any)["project_id"]; got != nil {
		t.Errorf("project_id after clearing = %v", got)
	}

	// API key limits.
	code, key := h.do("POST", "/v1/organizations/"+orgA.String()+"/api-keys", adminA,
		`{"alias":"k","project_id":"`+projA+`","rpm_limit":60,"tpm_limit":0}`)
	if code != http.StatusCreated || key["rpm_limit"] != float64(60) || key["tpm_limit"] != float64(0) {
		t.Fatalf("create key: %d %v", code, key)
	}
	prefix := key["key_prefix"].(string)
	if code, _ := h.do("POST", "/v1/organizations/"+orgA.String()+"/api-keys", adminA, `{"rpm_limit":-1}`); code != http.StatusBadRequest {
		t.Errorf("negative limit: %d, want 400", code)
	}
	if code, _ := h.do("POST", "/v1/organizations/"+orgA.String()+"/api-keys", adminA,
		`{"project_id":"`+projB["id"].(string)+`"}`); code != http.StatusBadRequest {
		t.Errorf("key in a foreign project: %d, want 400", code)
	}
	code, upd := h.do("PATCH", "/v1/organizations/"+orgA.String()+"/api-keys/"+prefix, adminA, `{"rpm_limit":null}`)
	if code != http.StatusOK || upd["rpm_limit"] != nil || upd["tpm_limit"] != float64(0) {
		t.Errorf("patch: %d %v", code, upd)
	}
	// Another org cannot change it.
	if code, _ := h.do("PATCH", "/v1/organizations/"+orgB.String()+"/api-keys/"+prefix, adminB, `{"rpm_limit":1}`); code != http.StatusNotFound {
		t.Errorf("foreign patch: %d, want 404", code)
	}
	_, keys := h.do("GET", "/v1/organizations/"+orgA.String()+"/api-keys", adminA, "")
	k := keys["data"].([]any)[0].(map[string]any)
	if k["rpm_limit"] != nil || k["tpm_limit"] != float64(0) || k["project_id"] != projA {
		t.Errorf("listed key = %v", k)
	}
}
