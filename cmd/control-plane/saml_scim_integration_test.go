//go:build integration

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// samlHarness is a control plane with one SAML provider of a test IdP.
type samlHarness struct {
	*cpHarness
	idp   *testIdP
	id    string // provider id
	sp    samlSPInfo
	admin string // instance admin token
}

func newSAMLHarness(t *testing.T, extra string) *samlHarness {
	t.Helper()
	h := newCPHarness(t, func(s *appSettings) { s.publicURL = "http://cp.test" })
	admin, _ := h.instanceAdmin()
	idp := newTestIdP(t, "https://idp.example.com/"+uuid.NewString())
	body, _ := json.Marshal(map[string]any{"type": "saml", "display_name": "Test IdP", "saml_metadata": idp.metadata(),
		"enabled": true, "auto_provision": true})
	if extra != "" {
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		var add map[string]any
		if err := json.Unmarshal([]byte(extra), &add); err != nil {
			t.Fatal(err)
		}
		for k, v := range add {
			m[k] = v
		}
		body, _ = json.Marshal(m)
	}
	out := h.expect(201, "POST", "/v1/admin/identity-providers", admin, string(body))
	sp, _ := out["saml_sp"].(map[string]any)
	pid, _ := out["id"].(string)
	info := samlSPInfo{EntityID: str(sp["entity_id"]), ACSURL: str(sp["acs_url"]), MetadataURL: str(sp["metadata_url"])}
	if info.ACSURL != "http://cp.test/v1/auth/saml/"+pid+"/acs" ||
		info.EntityID != "http://cp.test/v1/auth/saml/"+pid+"/metadata" {
		t.Fatalf("saml_sp %v", sp)
	}
	return &samlHarness{cpHarness: h, idp: idp, id: pid, sp: info, admin: admin}
}

func str(v any) string { s, _ := v.(string); return s }

// start begins an SP-initiated login and returns the AuthnRequest id and
// the browser cookie.
func (h *samlHarness) start(redirect string) (reqID, cookie string) {
	h.t.Helper()
	resp := h.req("GET", "/v1/auth/saml/"+h.id+"/start?redirect="+url.QueryEscape(redirect), "", "")
	if resp.StatusCode != 302 {
		body, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("start: %d %s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), h.idp.ssoURL+"?") {
		h.t.Fatalf("start location %q", resp.Header.Get("Location"))
	}
	raw, err := base64.StdEncoding.DecodeString(loc.Query().Get("SAMLRequest"))
	if err != nil {
		h.t.Fatal(err)
	}
	xml, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		h.t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xml); err != nil {
		h.t.Fatal(err)
	}
	reqID = doc.Root().SelectAttrValue("ID", "")
	if acs := doc.Root().SelectAttrValue("AssertionConsumerServiceURL", ""); acs != h.sp.ACSURL {
		h.t.Errorf("AuthnRequest ACS %q", acs)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == samlCookie {
			cookie = ck.Value
			if !ck.HttpOnly || ck.Path != "/v1/auth/saml" || ck.SameSite != http.SameSiteLaxMode {
				h.t.Errorf("cookie attributes %+v", ck)
			}
		}
	}
	if reqID == "" || cookie == "" {
		h.t.Fatalf("request id %q cookie %q", reqID, cookie)
	}
	return reqID, cookie
}

// acs posts a response and returns the query of the UI page it redirects to.
func (h *samlHarness) acs(response, cookie string) url.Values {
	h.t.Helper()
	form := url.Values{"SAMLResponse": {response}}.Encode()
	r := httptest.NewRequest("POST", "/v1/auth/saml/"+h.id+"/acs", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: samlCookie, Value: cookie})
	}
	resp, err := h.app.Test(r, -1)
	if err != nil {
		h.t.Fatal(err)
	}
	loc := resp.Header.Get("Location")
	path, query, ok := strings.Cut(loc, "?")
	if resp.StatusCode != 302 || !ok || path != callbackPath {
		body, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("acs: %d %q %s", resp.StatusCode, loc, body)
	}
	v, _ := url.ParseQuery(query)
	return v
}

// login runs a whole SP-initiated login and returns the session token.
func (h *samlHarness) login(o assertionOpts) (string, map[string]any) {
	h.t.Helper()
	reqID, cookie := h.start("/ui/")
	o.inResponseTo = reqID
	v := h.acs(h.idp.response(h.t, h.sp, o), cookie)
	if v.Get("code") == "" {
		h.t.Fatalf("login refused: %v", v)
	}
	out := h.expect(200, "POST", "/v1/auth/oidc/exchange", "", `{"code":"`+v.Get("code")+`"}`)
	token, _ := out["token"].(string)
	if token == "" {
		h.t.Fatalf("exchange %v", out)
	}
	return token, out
}

func TestSAMLLoginIntegration(t *testing.T) {
	h := newSAMLHarness(t, "")
	email := uniqueEmail()

	// Metadata is public.
	status, _ := h.raw("GET", "/v1/auth/saml/"+h.id+"/metadata", "", "", "")
	if status != 200 {
		t.Fatalf("metadata %d", status)
	}

	alice := "alice-" + uuid.NewString()
	token, out := h.login(assertionOpts{nameID: alice, email: email, name: "Alice"})
	me := h.expect(200, "GET", "/v1/auth/me", token, "")
	if me["email"] != strings.ToLower(email) {
		t.Errorf("me %v (exchange %v)", me, out)
	}
	var method string
	if err := h.db.QueryRow(context.Background(),
		`SELECT method FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1) ORDER BY created_at DESC LIMIT 1`,
		strings.ToLower(email)).Scan(&method); err != nil || method != "saml:"+h.id {
		t.Errorf("session method %q %v", method, err)
	}

	t.Run("response from another browser", func(t *testing.T) {
		reqID, _ := h.start("/ui/")
		_, other := h.start("/ui/")
		v := h.acs(h.idp.response(t, h.sp, assertionOpts{inResponseTo: reqID, email: email, nameID: alice}), other)
		if v.Get("error") != "invalid_state" {
			t.Errorf("got %v", v)
		}
	})
	t.Run("response for no pending request", func(t *testing.T) {
		_, cookie := h.start("/ui/")
		v := h.acs(h.idp.response(t, h.sp, assertionOpts{inResponseTo: "_unknown", email: email, nameID: alice}), cookie)
		if v.Get("error") != "invalid_state" {
			t.Errorf("got %v", v)
		}
	})
	t.Run("request answered twice", func(t *testing.T) {
		reqID, cookie := h.start("/ui/")
		resp := h.idp.response(t, h.sp, assertionOpts{inResponseTo: reqID, email: email, nameID: alice})
		if v := h.acs(resp, cookie); v.Get("code") == "" {
			t.Fatalf("first: %v", v)
		}
		if v := h.acs(resp, cookie); v.Get("error") != "invalid_state" {
			t.Errorf("second: %v", v)
		}
	})
	t.Run("idp-initiated off by default", func(t *testing.T) {
		v := h.acs(h.idp.response(t, h.sp, assertionOpts{email: email, nameID: alice}), "")
		if v.Get("error") != "idp_initiated_disabled" {
			t.Errorf("got %v", v)
		}
	})
	t.Run("bad signature", func(t *testing.T) {
		reqID, cookie := h.start("/ui/")
		other := newTestIdP(t, h.idp.entityID)
		v := h.acs(other.response(t, h.sp, assertionOpts{inResponseTo: reqID, email: email, nameID: alice}), cookie)
		if v.Get("error") == "" {
			t.Errorf("got %v", v)
		}
	})
}

func TestSAMLIdPInitiatedReplay(t *testing.T) {
	h := newSAMLHarness(t, `{"saml_allow_idp_initiated": true}`)
	resp := h.idp.response(t, h.sp, assertionOpts{nameID: "u-" + uuid.NewString(), email: uniqueEmail()})
	if v := h.acs(resp, ""); v.Get("code") == "" {
		t.Fatalf("first: %v", v)
	}
	if v := h.acs(resp, ""); v.Get("error") != "replayed" {
		t.Errorf("replay: %v", v)
	}
}

func TestSAMLDomainAndGroups(t *testing.T) {
	h := newSAMLHarness(t, `{"allowed_domains": ["example.com"]}`)
	if v := h.acs(func() string {
		reqID, _ := h.start("/ui/")
		return h.idp.response(t, h.sp, assertionOpts{inResponseTo: reqID, email: "eve@evil.test"})
	}(), ""); v.Get("error") == "" {
		t.Errorf("no cookie and wrong domain: %v", v)
	}
	reqID, cookie := h.start("/ui/")
	if v := h.acs(h.idp.response(t, h.sp, assertionOpts{inResponseTo: reqID, email: "eve@evil.test"}), cookie); v.Get("error") != "domain_not_allowed" {
		t.Errorf("domain: %v", v)
	}

	// A member's role follows the mapped groups at login; an owner's never.
	org, _, owner := h.org(auth.RoleOwner)
	pidJSON := `"` + h.id + `"`
	h.expect(200, "PUT", "/v1/organizations/"+org.String()+"/group-roles", owner,
		`{"items":[{"provider_id":`+pidJSON+`,"group_key":"GS-Admins","role":"admin"},
		           {"provider_id":`+pidJSON+`,"group_key":"gs-readers","role":"viewer"}]}`)
	email := uniqueEmail()
	nameID := "bob-" + uuid.NewString()
	h.login(assertionOpts{nameID: nameID, email: email})
	var user uuid.UUID
	if err := h.db.QueryRow(context.Background(), `SELECT id FROM users WHERE email = $1`, strings.ToLower(email)).Scan(&user); err != nil {
		t.Fatal(err)
	}
	h.addMember(org, user, auth.RoleMember)
	h.login(assertionOpts{nameID: nameID, email: email, groups: []string{"gs-admins", "gs-readers"}})
	if r := h.role(user, org); r != "admin" {
		t.Errorf("highest mapped role: %q", r)
	}
	h.login(assertionOpts{nameID: nameID, email: email, groups: []string{"gs-readers"}})
	if r := h.role(user, org); r != "viewer" {
		t.Errorf("readers: %q", r)
	}
	h.login(assertionOpts{nameID: nameID, email: email, groups: []string{"gs-admins"}})
	h.login(assertionOpts{nameID: nameID, email: email, groups: []string{"unmapped"}})
	if r := h.role(user, org); r != "member" {
		t.Errorf("leaving the mapped groups must drop to the default role: %q", r)
	}
	h.login(assertionOpts{nameID: nameID, email: email, groups: []string{"gs-admins"}})
	h.login(assertionOpts{nameID: nameID, email: email})
	if r := h.role(user, org); r != "member" {
		t.Errorf("no groups at all must drop to the default role: %q", r)
	}
	// An org that maps no group of this provider is left alone.
	other, _, _ := h.org(auth.RoleOwner)
	h.addMember(other, user, auth.RoleAdmin)
	h.login(assertionOpts{nameID: nameID, email: email, groups: []string{"gs-readers"}})
	if r := h.role(user, other); r != "admin" {
		t.Errorf("unmapped org changed: %q", r)
	}
	if err := tenant.WithOrg(context.Background(), h.db, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE org_memberships SET role = 'owner' WHERE user_id = $1 AND org_id = $2`, user, org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.login(assertionOpts{nameID: nameID, email: email, groups: []string{"gs-readers"}})
	if r := h.role(user, org); r != "owner" {
		t.Errorf("owner changed by a group: %q", r)
	}
}

// scimDo sends a SCIM request with a bearer token.
func (h *cpHarness) scimDo(method, path, token, body string) (int, map[string]any) {
	h.t.Helper()
	r := httptest.NewRequest(method, "/v1/scim/v2"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/scim+json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.app.Test(r, -1)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	if ct := resp.Header.Get("Content-Type"); len(data) > 0 && !strings.HasPrefix(ct, "application/scim+json") {
		h.t.Errorf("%s %s: content type %q", method, path, ct)
	}
	return resp.StatusCode, out
}

func (h *cpHarness) scimExpect(want int, method, path, token, body string) map[string]any {
	h.t.Helper()
	status, out := h.scimDo(method, path, token, body)
	if status != want {
		h.t.Fatalf("SCIM %s %s: %d, want %d: %v", method, path, status, want, out)
	}
	return out
}

func (h *cpHarness) scimToken(org uuid.UUID, owner string) (string, string) {
	h.t.Helper()
	out := h.expect(201, "POST", "/v1/organizations/"+org.String()+"/scim/tokens", owner, `{"name":"okta"}`)
	tok, _ := out["token"].(string)
	item, _ := out["item"].(map[string]any)
	if !strings.HasPrefix(tok, "gss_") {
		h.t.Fatalf("token %v", out)
	}
	return tok, str(item["id"])
}

func TestSCIMTokensIntegration(t *testing.T) {
	h := newCPHarness(t, func(s *appSettings) { s.publicURL = "http://cp.test" })
	org, _, owner := h.org(auth.RoleOwner)
	admin := h.member(org, auth.RoleAdmin)
	base := "/v1/organizations/" + org.String() + "/scim/tokens"
	h.expect(403, "POST", base, admin, `{"name":"x"}`)
	tok, tid := h.scimToken(org, owner)
	list := h.expect(200, "GET", base, admin, "")
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), tok) || !strings.Contains(string(raw), "http://cp.test/v1/scim/v2") {
		t.Errorf("list leaks the token or lacks the base url: %s", raw)
	}
	h.scimExpect(200, "GET", "/ServiceProviderConfig", tok, "")
	if status, _ := h.scimDo("GET", "/Users", "", ""); status != 401 {
		t.Errorf("no token: %d", status)
	}
	if status, _ := h.scimDo("GET", "/Users", "gss_"+strings.Repeat("a", 40), ""); status != 401 {
		t.Errorf("unknown token: %d", status)
	}
	h.expect(403, "DELETE", base+"/"+tid, admin, "")
	h.expect(204, "DELETE", base+"/"+tid, owner, "")
	if status, _ := h.scimDo("GET", "/Users", tok, ""); status != 401 {
		t.Errorf("revoked token: %d", status)
	}
}

func TestSCIMProvisioningIntegration(t *testing.T) {
	h := newCPHarness(t, func(s *appSettings) { s.publicURL = "http://cp.test" })
	ctx := context.Background()
	org, _, owner := h.org(auth.RoleOwner)
	tok, _ := h.scimToken(org, owner)
	// SCIM group "Engineering" grants admin.
	h.expect(200, "PUT", "/v1/organizations/"+org.String()+"/group-roles", owner,
		`{"items":[{"provider_id":null,"group_key":"engineering","role":"admin"}]}`)

	email := uniqueEmail()
	created := h.scimExpect(201, "POST", "/Users", tok, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"`+email+`","externalId":"00u1","name":{"givenName":"Ann","familyName":"Lee"},
		"emails":[{"value":"`+email+`","primary":true}],"active":true}`)
	sid := str(created["id"])
	h.scimExpect(409, "POST", "/Users", tok, `{"userName":"`+strings.ToUpper(email)+`"}`)
	found := h.scimExpect(200, "GET", "/Users?filter="+url.QueryEscape(`userName eq "`+email+`"`), tok, "")
	if found["totalResults"] != float64(1) {
		t.Errorf("filter: %v", found)
	}
	var user uuid.UUID
	if err := h.db.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, strings.ToLower(email)).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if r := h.role(user, org); r != "member" {
		t.Errorf("new user role %q", r)
	}

	group := h.scimExpect(201, "POST", "/Groups", tok, `{"displayName":"Engineering","members":[{"value":"`+sid+`"}]}`)
	gid := str(group["id"])
	if r := h.role(user, org); r != "admin" {
		t.Errorf("group role %q", r)
	}

	// The user creates an API key and has a session.
	session, err := h.sessionToken(user)
	if err != nil {
		t.Fatal(err)
	}
	h.expect(201, "POST", "/v1/organizations/"+org.String()+"/api-keys", session, `{"alias":"ann"}`)

	// Okta deactivates with a PATCH without a path.
	h.scimExpect(200, "PATCH", "/Users/"+sid, tok,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`)
	if r := h.role(user, org); r != "" {
		t.Errorf("deactivated user keeps role %q", r)
	}
	if status, _ := h.do("GET", "/v1/auth/me", session, ""); status != 401 {
		t.Errorf("session after deactivation: %d", status)
	}
	var live, total int
	if err := tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE revoked_at IS NULL), count(*) FROM api_keys
			WHERE org_id = $1 AND created_by = $2`, org, user).Scan(&live, &total)
	}); err != nil || live != 0 || total != 1 {
		t.Errorf("keys after deactivation: %d live of %d, %v", live, total, err)
	}

	// Entra reactivates with a string boolean; the group role comes back.
	h.scimExpect(200, "PATCH", "/Users/"+sid, tok,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"True"}]}`)
	if r := h.role(user, org); r != "admin" {
		t.Errorf("reactivated role %q", r)
	}

	// Removing the member drops the mapped role back to the default.
	h.scimExpect(200, "PATCH", "/Groups/"+gid, tok,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"`+sid+`\"]"}]}`)
	if r := h.role(user, org); r != "member" {
		t.Errorf("role after leaving the group %q", r)
	}

	// Another org's token sees nothing of this org.
	other, _, otherOwner := h.org(auth.RoleOwner)
	otherTok, _ := h.scimToken(other, otherOwner)
	if status, _ := h.scimDo("GET", "/Users/"+sid, otherTok, ""); status != 404 {
		t.Errorf("cross-org get: %d", status)
	}
	if status, _ := h.scimDo("DELETE", "/Groups/"+gid, otherTok, ""); status != 404 {
		t.Errorf("cross-org delete: %d", status)
	}
	listed := h.scimExpect(200, "GET", "/Users", otherTok, "")
	if listed["totalResults"] != float64(0) {
		t.Errorf("cross-org list: %v", listed)
	}

	h.scimExpect(204, "DELETE", "/Users/"+sid, tok, "")
	if r := h.role(user, org); r != "" {
		t.Errorf("deleted user keeps role %q", r)
	}
	h.scimExpect(404, "GET", "/Users/"+sid, tok, "")
}

func TestSCIMSoleOwnerAndLinking(t *testing.T) {
	h := newCPHarness(t, func(s *appSettings) { s.publicURL = "http://cp.test" })
	ctx := context.Background()
	org, ownerID, owner := h.org(auth.RoleOwner)
	tok, _ := h.scimToken(org, owner)
	var ownerEmail string
	if err := h.db.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, ownerID).Scan(&ownerEmail); err != nil {
		t.Fatal(err)
	}
	// An existing member is linked, not duplicated.
	linked := h.scimExpect(201, "POST", "/Users", tok, `{"userName":"`+ownerEmail+`"}`)
	// The sole owner cannot be deactivated.
	if status, _ := h.scimDo("PATCH", "/Users/"+str(linked["id"]), tok,
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`); status < 400 {
		t.Errorf("sole owner deactivated: %d", status)
	}
	if r := h.role(ownerID, org); r != "owner" {
		t.Errorf("owner role %q", r)
	}
	// An account outside the org, of an unclaimed domain, is not taken over.
	_, outsider := h.user("outsider-password-1")
	var outsiderEmail string
	if err := h.db.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, outsider).Scan(&outsiderEmail); err != nil {
		t.Fatal(err)
	}
	if status, _ := h.scimDo("POST", "/Users", tok, `{"userName":"`+outsiderEmail+`"}`); status != 409 {
		t.Errorf("outsider account: %d", status)
	}
	if r := h.role(outsider, org); r != "" {
		t.Errorf("outsider joined: %q", r)
	}
}

func TestSAMLProfileLink(t *testing.T) {
	h := newSAMLHarness(t, "")
	email := uniqueEmail()
	user := h.passwordUser(email, "link-password-123")
	token, err := h.sessionToken(user)
	if err != nil {
		t.Fatal(err)
	}
	nameID := "linked-" + uuid.NewString()
	// A login with the same email is refused: the account has a password.
	reqID, cookie := h.start("/ui/")
	if v := h.acs(h.idp.response(t, h.sp, assertionOpts{inResponseTo: reqID, nameID: nameID, email: email}), cookie); v.Get("error") != "account_exists" {
		t.Fatalf("login before link: %v", v)
	}
	// The owner links from the profile; the response needs no browser cookie.
	out := h.expect(200, "POST", "/v1/auth/identities/"+h.id+"/link/start", token, "")
	to, _ := url.Parse(str(out["url"]))
	raw, _ := base64.StdEncoding.DecodeString(to.Query().Get("SAMLRequest"))
	xml, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xml); err != nil {
		t.Fatal(err)
	}
	linkReq := doc.Root().SelectAttrValue("ID", "")
	form := url.Values{"SAMLResponse": {h.idp.response(t, h.sp, assertionOpts{inResponseTo: linkReq, nameID: nameID, email: email})}}.Encode()
	r := httptest.NewRequest("POST", "/v1/auth/saml/"+h.id+"/acs", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	path, query, _ := strings.Cut(resp.Header.Get("Location"), "?")
	v, _ := url.ParseQuery(query)
	if resp.StatusCode != 302 || path != accountPath || v.Get("link_code") == "" {
		t.Fatalf("link acs: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Someone else cannot complete it.
	other, _ := h.user("other-password-123")
	h.expect(409, "POST", "/v1/auth/identities/link/complete", other, `{"code":"`+v.Get("link_code")+`"}`)
	h.expect(200, "POST", "/v1/auth/identities/link/complete", token, `{"code":"`+v.Get("link_code")+`"}`)
	// Now the SAML login signs in to the same account.
	saml, _ := h.login(assertionOpts{nameID: nameID, email: email})
	me := h.expect(200, "GET", "/v1/auth/me", saml, "")
	if me["id"] != user.String() {
		t.Errorf("logged in as %v, want %s", me["id"], user)
	}
	// Members lists show the method as saml:<id>.
	org, _, owner := h.org(auth.RoleOwner)
	h.addMember(org, user, auth.RoleMember)
	list := h.expect(200, "GET", "/v1/organizations/"+org.String()+"/members", owner, "")
	raw2, _ := json.Marshal(list)
	if !strings.Contains(string(raw2), `"saml:`+h.id+`"`) {
		t.Errorf("members: %s", raw2)
	}
}

func TestSCIMLifecycleEdges(t *testing.T) {
	h := newCPHarness(t, func(s *appSettings) { s.publicURL = "http://cp.test" })
	ctx := context.Background()
	org, _, owner := h.org(auth.RoleOwner)
	tok, _ := h.scimToken(org, owner)

	// An existing member provisioned as inactive loses the membership.
	_, member := h.user("member-password-1")
	h.addMember(org, member, auth.RoleAdmin)
	var memberEmail string
	if err := h.db.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, member).Scan(&memberEmail); err != nil {
		t.Fatal(err)
	}
	inactive := h.scimExpect(201, "POST", "/Users", tok, `{"userName":"`+memberEmail+`","active":false}`)
	if inactive["active"] != false || h.role(member, org) != "" {
		t.Errorf("inactive create: %v, role %q", inactive, h.role(member, org))
	}
	// Reactivated without a mapping: the role they had.
	h.scimExpect(200, "PATCH", "/Users/"+str(inactive["id"]), tok, `{"Operations":[{"op":"replace","value":{"active":true}}]}`)
	if r := h.role(member, org); r != "admin" {
		t.Errorf("reactivated without mappings: %q", r)
	}

	// With SCIM mappings a reactivated user outside mapped groups is a member.
	h.expect(200, "PUT", "/v1/organizations/"+org.String()+"/group-roles", owner,
		`{"items":[{"provider_id":null,"group_key":"admins","role":"admin"}]}`)
	h.scimExpect(200, "PATCH", "/Users/"+str(inactive["id"]), tok, `{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	h.scimExpect(200, "PATCH", "/Users/"+str(inactive["id"]), tok, `{"Operations":[{"op":"replace","path":"active","value":true}]}`)
	if r := h.role(member, org); r != "member" {
		t.Errorf("reactivated with mappings: %q", r)
	}

	// A path-less replace of members replaces them.
	a := h.scimExpect(201, "POST", "/Users", tok, `{"userName":"`+uniqueEmail()+`"}`)
	b := h.scimExpect(201, "POST", "/Users", tok, `{"userName":"`+uniqueEmail()+`"}`)
	g := h.scimExpect(201, "POST", "/Groups", tok, `{"displayName":"admins","members":[{"value":"`+str(a["id"])+`"}]}`)
	h.scimExpect(200, "PATCH", "/Groups/"+str(g["id"]), tok,
		`{"Operations":[{"op":"replace","value":{"members":[{"value":"`+str(b["id"])+`"}]}}]}`)
	got := h.scimExpect(200, "GET", "/Groups/"+str(g["id"]), tok, "")
	members, _ := got["members"].([]any)
	if len(members) != 1 || str(members[0].(map[string]any)["value"]) != str(b["id"]) {
		t.Errorf("members after replace: %v", got["members"])
	}

	// A SCIM-created account disabled by deactivation stays disabled when an
	// administrator disabled it again in between.
	c := h.scimExpect(201, "POST", "/Users", tok, `{"userName":"`+uniqueEmail()+`"}`)
	var cu uuid.UUID
	if err := tenant.WithOrg(ctx, h.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT user_id FROM scim_users WHERE id = $1`, str(c["id"])).Scan(&cu)
	}); err != nil {
		t.Fatal(err)
	}
	h.scimExpect(200, "PATCH", "/Users/"+str(c["id"]), tok, `{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	disabled := func() bool {
		var d bool
		if err := h.db.QueryRow(ctx, `SELECT disabled_at IS NOT NULL FROM users WHERE id = $1`, cu).Scan(&d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if !disabled() {
		t.Fatal("deactivation did not disable the SCIM-created account")
	}
	if _, err := h.db.Exec(ctx, `UPDATE users SET disabled_at = NOW() + interval '1 second' WHERE id = $1`, cu); err != nil {
		t.Fatal(err)
	}
	h.scimExpect(200, "PATCH", "/Users/"+str(c["id"]), tok, `{"Operations":[{"op":"replace","path":"active","value":true}]}`)
	if !disabled() {
		t.Error("reactivation undid an administrator's disabling")
	}
}
