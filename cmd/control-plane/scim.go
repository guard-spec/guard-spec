// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SCIM 2.0 provisioning (RFC 7643, RFC 7644; migration 025).
//
// Each organization has its own SCIM tokens: the token names the org, so the
// base URL is the same for every org (<PUBLIC_BASE_URL>/v1/scim/v2). The
// identity provider (Okta, Microsoft Entra ID, Keycloak with a SCIM plugin…)
// creates, updates, deactivates and deletes the org's users and groups.
//
// Users. userName (or the primary email) is the account's email. A new
// email creates an account without a password: the person logs in with SSO.
// An existing account is linked only if it is already a member of the org or
// its email domain is one the org claims (a domain_join rule, which an
// instance administrator must have allowed): otherwise any org could take
// over, or lock out, someone else's account. A provisioned user gets the
// member role, or the highest role their SCIM groups map to (org_group_roles).
//
// active false (or DELETE) removes the membership at once (RequireRole reads
// it on every request) and keeps its role for a reactivation; revokes the API
// keys the user created in the org (org_security.scim_revoke_keys, default
// on); and, for an account the org owns (created by its SCIM or in a claimed
// domain), revokes every session and disables the account when the org is
// its only one. Owners are never changed through a group; the last owner
// cannot be deactivated.

const (
	scimUserSchema   = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema  = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchSchema  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimContentType  = "application/scim+json"
	scimTokenPrefix  = "gss_"
	scimMaxPage      = 200
	scimMaxMembers   = 1000
	scimLocalsOrg    = "scim_org"
	scimLocalsToken  = "scim_token"
	scimDefaultRole  = "member"
	maxSCIMTokens    = 20
	scimBasePath     = "/v1/scim/v2"
	scimNameMax      = 320
	scimExternalMax  = 256
	scimDisplayMax   = 256
	scimFilterMaxLen = 512
)

var scimFilterRe = regexp.MustCompile(`(?i)^\s*([a-z][a-z0-9.]*)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$`)

type scimAPI struct {
	db       *pgxpool.Pool
	sessions *auth.Sessions
	base     string // public URL of /v1/scim/v2, for meta.location
}

// scimErr is a SCIM error answer.
type scimErr struct {
	status   int
	scimType string
	detail   string
}

func (e *scimErr) Error() string { return e.detail }

func scimError(status int, scimType, detail string) error {
	return &scimErr{status: status, scimType: scimType, detail: detail}
}

func (s *scimAPI) reply(c *fiber.Ctx, status int, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return serverError(c, err)
	}
	c.Set(fiber.HeaderContentType, scimContentType)
	return c.Status(status).Send(b)
}

// fail answers err as a SCIM error (an unexpected error is a 500).
func (s *scimAPI) fail(c *fiber.Ctx, err error) error {
	var se *scimErr
	if !errors.As(err, &se) {
		_ = serverError(c, err)
		se = &scimErr{status: 500, detail: "internal error"}
	}
	body := fiber.Map{"schemas": []string{scimErrorSchema}, "status": strconv.Itoa(se.status), "detail": se.detail}
	if se.scimType != "" {
		body["scimType"] = se.scimType
	}
	return s.reply(c, se.status, body)
}

// authenticate resolves the bearer token to its organization.
func (s *scimAPI) authenticate(c *fiber.Ctx) error {
	h := c.Get(fiber.HeaderAuthorization)
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || !strings.HasPrefix(tok, scimTokenPrefix) || len(tok) > 200 {
		c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="scim"`)
		return s.fail(c, scimError(401, "", "a valid SCIM bearer token is required"))
	}
	var tokenID, org uuid.UUID
	err := s.db.QueryRow(c.Context(), `SELECT token_id, org_id FROM lookup_scim_token($1)`, tenant.HashKey(tok)).
		Scan(&tokenID, &org)
	if errors.Is(err, pgx.ErrNoRows) {
		c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="scim"`)
		return s.fail(c, scimError(401, "", "a valid SCIM bearer token is required"))
	}
	if err != nil {
		return s.fail(c, err)
	}
	c.Locals(scimLocalsOrg, org)
	c.Locals(scimLocalsToken, tokenID)
	return c.Next()
}

func scimOrg(c *fiber.Ctx) uuid.UUID {
	v, _ := c.Locals(scimLocalsOrg).(uuid.UUID)
	return v
}

// activity records a SCIM change; the actor is the token.
func (s *scimAPI) activity(c *fiber.Ctx, action, target string, details map[string]any) {
	org := scimOrg(c)
	if details == nil {
		details = map[string]any{}
	}
	details["scim_token_id"] = c.Locals(scimLocalsToken)
	writeActivity(c.Context(), s.db, activityEntry{Org: &org, Action: action, Target: target, IP: clientIP(c), Details: details})
}

// ── Discovery ────────────────────────────────────────────────────────────────

func (s *scimAPI) serviceProviderConfig(c *fiber.Ctx) error {
	return s.reply(c, 200, fiber.Map{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://guardspec.io/docs/sso",
		"patch":            fiber.Map{"supported": true},
		"bulk":             fiber.Map{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           fiber.Map{"supported": true, "maxResults": scimMaxPage},
		"changePassword":   fiber.Map{"supported": false},
		"sort":             fiber.Map{"supported": false},
		"etag":             fiber.Map{"supported": false},
		"authenticationSchemes": []fiber.Map{{"type": "oauthbearertoken", "name": "Bearer token",
			"description": "An organization's SCIM token (Organization → Provisioning)", "primary": true}},
		"meta": fiber.Map{"resourceType": "ServiceProviderConfig", "location": s.base + "/ServiceProviderConfig"},
	})
}

func (s *scimAPI) resourceTypes(c *fiber.Ctx) error {
	types := []fiber.Map{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User",
			"endpoint": "/Users", "schema": scimUserSchema, "meta": fiber.Map{"resourceType": "ResourceType", "location": s.base + "/ResourceTypes/User"}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group",
			"endpoint": "/Groups", "schema": scimGroupSchema, "meta": fiber.Map{"resourceType": "ResourceType", "location": s.base + "/ResourceTypes/Group"}},
	}
	return s.reply(c, 200, fiber.Map{"schemas": []string{scimListSchema}, "totalResults": len(types), "startIndex": 1,
		"itemsPerPage": len(types), "Resources": types})
}

func (s *scimAPI) schemas(c *fiber.Ctx) error {
	attr := func(name, typ string, required bool) fiber.Map {
		return fiber.Map{"name": name, "type": typ, "multiValued": false, "required": required, "mutability": "readWrite",
			"returned": "default", "uniqueness": "none", "caseExact": false}
	}
	list := []fiber.Map{
		{"id": scimUserSchema, "name": "User", "attributes": []fiber.Map{attr("userName", "string", true),
			attr("displayName", "string", false), attr("active", "boolean", false), attr("externalId", "string", false)},
			"meta": fiber.Map{"resourceType": "Schema", "location": s.base + "/Schemas/" + scimUserSchema}},
		{"id": scimGroupSchema, "name": "Group", "attributes": []fiber.Map{attr("displayName", "string", true),
			attr("externalId", "string", false)},
			"meta": fiber.Map{"resourceType": "Schema", "location": s.base + "/Schemas/" + scimGroupSchema}},
	}
	return s.reply(c, 200, fiber.Map{"schemas": []string{scimListSchema}, "totalResults": len(list), "startIndex": 1,
		"itemsPerPage": len(list), "Resources": list})
}

// ── Users ────────────────────────────────────────────────────────────────────

type scimUserRow struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	ExternalID  *string
	UserName    string
	Active      bool
	Email       string
	DisplayName *string
	Created     time.Time
	Updated     time.Time
	Groups      []scimRef
}

type scimRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

const scimUserColumns = `s.id, s.user_id, s.external_id, s.user_name, s.active, u.email, u.display_name, s.created_at, s.updated_at`

func scanSCIMUser(r pgx.Row) (scimUserRow, error) {
	var u scimUserRow
	err := r.Scan(&u.ID, &u.UserID, &u.ExternalID, &u.UserName, &u.Active, &u.Email, &u.DisplayName, &u.Created, &u.Updated)
	return u, err
}

func (s *scimAPI) userJSON(u scimUserRow) fiber.Map {
	m := fiber.Map{
		"schemas":  []string{scimUserSchema},
		"id":       u.ID.String(),
		"userName": u.UserName,
		"active":   u.Active,
		"emails":   []fiber.Map{{"value": u.Email, "primary": true, "type": "work"}},
		"groups":   u.Groups,
		"meta": fiber.Map{"resourceType": "User", "created": u.Created.UTC().Format(time.RFC3339),
			"lastModified": u.Updated.UTC().Format(time.RFC3339), "location": s.base + "/Users/" + u.ID.String()},
	}
	if u.Groups == nil {
		m["groups"] = []scimRef{}
	}
	if u.ExternalID != nil {
		m["externalId"] = *u.ExternalID
	}
	if u.DisplayName != nil {
		m["displayName"] = *u.DisplayName
		m["name"] = fiber.Map{"formatted": *u.DisplayName}
	}
	return m
}

func (s *scimAPI) userGroups(ctx context.Context, tx pgx.Tx, u *scimUserRow) error {
	rows, err := tx.Query(ctx,
		`SELECT g.id::text, g.display_name FROM scim_group_members m JOIN scim_groups g ON g.id = m.group_id
		 WHERE m.scim_user_id = $1 ORDER BY g.display_name`, u.ID)
	if err != nil {
		return err
	}
	u.Groups, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (scimRef, error) {
		var x scimRef
		err := r.Scan(&x.Value, &x.Display)
		x.Ref = s.base + "/Groups/" + x.Value
		return x, err
	})
	return err
}

// paging reads startIndex (1-based) and count.
func paging(c *fiber.Ctx) (int, int) {
	start, _ := strconv.Atoi(c.Query("startIndex", "1"))
	if start < 1 {
		start = 1
	}
	count, err := strconv.Atoi(c.Query("count", "100"))
	if err != nil || count < 0 {
		count = 100
	}
	return start, min(count, scimMaxPage)
}

// parseFilter reads `attr eq "value"` for the attributes in allowed.
func parseFilter(raw string, allowed map[string]string) (column, value string, err error) {
	if raw == "" {
		return "", "", nil
	}
	if len(raw) > scimFilterMaxLen {
		return "", "", scimError(400, "invalidFilter", "the filter is too long")
	}
	m := scimFilterRe.FindStringSubmatch(raw)
	if m == nil {
		return "", "", scimError(400, "invalidFilter", `only filters of the form attribute eq "value" are supported`)
	}
	col, ok := allowed[strings.ToLower(m[1])]
	if !ok {
		return "", "", scimError(400, "invalidFilter", "filtering on "+m[1]+" is not supported")
	}
	v, uerr := strconv.Unquote(`"` + m[2] + `"`)
	if uerr != nil {
		return "", "", scimError(400, "invalidFilter", "the filter value cannot be read")
	}
	return col, v, nil
}

func (s *scimAPI) listUsers(c *fiber.Ctx) error {
	org := scimOrg(c)
	col, val, err := parseFilter(c.Query("filter"), map[string]string{
		"username": "lower(s.user_name) = lower($2)", "externalid": "s.external_id = $2", "id": "s.id::text = $2",
		"emails.value": "u.email = lower($2)"})
	if err != nil {
		return s.fail(c, err)
	}
	start, count := paging(c)
	where := "s.org_id = $1"
	args := []any{org}
	if col != "" {
		where += " AND " + col
		args = append(args, val)
	}
	var total int
	var list []scimUserRow
	err = tenant.WithOrg(c.Context(), s.db, org, func(tx pgx.Tx) error {
		if err := tx.QueryRow(c.Context(), `SELECT count(*) FROM scim_users s JOIN users u ON u.id = s.user_id WHERE `+where,
			args...).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(), `SELECT `+scimUserColumns+` FROM scim_users s JOIN users u ON u.id = s.user_id
			WHERE `+where+fmt.Sprintf(` ORDER BY s.created_at, s.id OFFSET %d LIMIT %d`, start-1, count), args...)
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (scimUserRow, error) { return scanSCIMUser(r) })
		if err != nil {
			return err
		}
		for i := range list {
			if err := s.userGroups(c.Context(), tx, &list[i]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return s.fail(c, err)
	}
	res := make([]fiber.Map, 0, len(list))
	for _, u := range list {
		res = append(res, s.userJSON(u))
	}
	return s.reply(c, 200, fiber.Map{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": start,
		"itemsPerPage": len(res), "Resources": res})
}

func (s *scimAPI) loadUser(ctx context.Context, tx pgx.Tx, org uuid.UUID, id string) (scimUserRow, error) {
	sid, err := uuid.Parse(id)
	if err != nil {
		return scimUserRow{}, scimError(404, "", "user not found")
	}
	u, err := scanSCIMUser(tx.QueryRow(ctx, `SELECT `+scimUserColumns+` FROM scim_users s JOIN users u ON u.id = s.user_id
		WHERE s.org_id = $1 AND s.id = $2`, org, sid))
	if errors.Is(err, pgx.ErrNoRows) {
		return u, scimError(404, "", "user not found")
	}
	if err != nil {
		return u, err
	}
	return u, s.userGroups(ctx, tx, &u)
}

func (s *scimAPI) getUser(c *fiber.Ctx) error {
	org := scimOrg(c)
	var u scimUserRow
	err := tenant.WithOrg(c.Context(), s.db, org, func(tx pgx.Tx) error {
		var err error
		u, err = s.loadUser(c.Context(), tx, org, c.Params("id"))
		return err
	})
	if err != nil {
		return s.fail(c, err)
	}
	return s.reply(c, 200, s.userJSON(u))
}

// userInput is the part of a User resource Guard Spec uses.
type userInput struct {
	UserName    *string `json:"userName"`
	ExternalID  *string `json:"externalId"`
	DisplayName *string `json:"displayName"`
	Name        *struct {
		Formatted  string `json:"formatted"`
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary any    `json:"primary"`
	} `json:"emails"`
	Active any `json:"active"`
}

// scimBool reads a SCIM boolean; Entra ID sends "True" / "False" strings.
func scimBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// email is the account email: userName when it is one, else the primary
// (or first) email.
func (in userInput) email() string {
	if in.UserName != nil {
		if e := strings.ToLower(strings.TrimSpace(*in.UserName)); validEmail(e) {
			return e
		}
	}
	for _, primaryOnly := range []bool{true, false} {
		for _, e := range in.Emails {
			if p, _ := scimBool(e.Primary); p || !primaryOnly {
				if v := strings.ToLower(strings.TrimSpace(e.Value)); validEmail(v) {
					return v
				}
			}
		}
	}
	return ""
}

func (in userInput) display() *string {
	var d string
	switch {
	case in.DisplayName != nil:
		d = *in.DisplayName
	case in.Name != nil && in.Name.Formatted != "":
		d = in.Name.Formatted
	case in.Name != nil:
		d = strings.TrimSpace(in.Name.GivenName + " " + in.Name.FamilyName)
	}
	d = strings.TrimSpace(d)
	if d == "" {
		return nil
	}
	d = truncateRunes(d, 200)
	return &d
}

func validExternalID(p *string) error {
	if p != nil && len(*p) > scimExternalMax {
		return scimError(400, "invalidValue", "externalId is too long")
	}
	return nil
}

// orgClaims reports whether the org claims the email's domain (domain_join).
func orgClaims(ctx context.Context, db *pgxpool.Pool, org uuid.UUID, email string) (bool, error) {
	sec, err := loadOrgSecurity(ctx, db, org)
	if err != nil {
		return false, err
	}
	d := emailDomain(email)
	return slices.ContainsFunc(sec.DomainJoin, func(r domainJoinRule) bool { return r.Domain == d }), nil
}

func (s *scimAPI) createUser(c *fiber.Ctx) error {
	ctx := c.Context()
	org := scimOrg(c)
	var in userInput
	if err := json.Unmarshal(c.Body(), &in); err != nil {
		return s.fail(c, scimError(400, "invalidSyntax", "the body is not a SCIM User"))
	}
	var effect deactivation
	email := in.email()
	if in.UserName == nil || strings.TrimSpace(*in.UserName) == "" || len(*in.UserName) > scimNameMax {
		return s.fail(c, scimError(400, "invalidValue", "userName is required"))
	}
	if email == "" {
		return s.fail(c, scimError(400, "invalidValue", "userName or a primary email must be an email address"))
	}
	if err := validExternalID(in.ExternalID); err != nil {
		return s.fail(c, err)
	}
	active := true
	if in.Active != nil {
		v, ok := scimBool(in.Active)
		if !ok {
			return s.fail(c, scimError(400, "invalidValue", "active must be a boolean"))
		}
		active = v
	}
	claimed, err := orgClaims(ctx, s.db, org, email)
	if err != nil {
		return s.fail(c, err)
	}
	userName := strings.TrimSpace(*in.UserName)
	var u scimUserRow
	err = tenant.WithOrg(ctx, s.db, org, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scim_users WHERE org_id = $1 AND lower(user_name) = lower($2))`,
			org, userName).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return scimError(409, "uniqueness", "a user with this userName exists")
		}
		var user uuid.UUID
		created := false
		var member bool
		err := tx.QueryRow(ctx, `SELECT u.id, EXISTS (SELECT 1 FROM org_memberships m WHERE m.user_id = u.id AND m.org_id = $2)
			FROM users u WHERE u.email = $1 FOR UPDATE`, email, org).Scan(&user, &member)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if err := tx.QueryRow(ctx, `INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id`,
				email, in.display()).Scan(&user); err != nil {
				return err
			}
			created = true
		case err != nil:
			return err
		case !member && !claimed:
			// Someone else's account: linking it would let this org lock its
			// owner out. They join by invite, or the org claims the domain.
			return scimError(409, "uniqueness",
				"an account with this email exists outside this organization; invite it, or claim its domain (domain_join)")
		}
		var sid uuid.UUID
		if err := tx.QueryRow(ctx,
			`INSERT INTO scim_users (org_id, user_id, external_id, user_name, active, created, suspended_role)
			 VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $5 THEN NULL ELSE $7::org_role END) RETURNING id`,
			org, user, in.ExternalID, userName, active, created, scimDefaultRole).Scan(&sid); err != nil {
			if isUniqueViolation(err) {
				return scimError(409, "uniqueness", "this account is already provisioned in this organization")
			}
			return err
		}
		switch {
		case active:
			if _, err := tx.Exec(ctx, `INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, $3::org_role)
				ON CONFLICT DO NOTHING`, user, org, scimDefaultRole); err != nil {
				return err
			}
		case member:
			// An existing member provisioned as inactive loses the membership,
			// as a deactivation would take it.
			if _, err := tx.Exec(ctx, `UPDATE scim_users SET active = true, suspended_role = NULL WHERE id = $1`, sid); err != nil {
				return err
			}
			if effect, err = s.deactivate(ctx, tx, org, sid); err != nil {
				return err
			}
		}
		u, err = s.loadUser(ctx, tx, org, sid.String())
		return err
	})
	if err != nil {
		return s.fail(c, err)
	}
	if err := s.afterDeactivate(c, u.UserID, effect); err != nil {
		return s.fail(c, err)
	}
	s.activity(c, "scim.user_created", u.UserID.String(), map[string]any{"user_name": u.UserName, "active": u.Active})
	c.Set(fiber.HeaderLocation, s.base+"/Users/"+u.ID.String())
	return s.reply(c, 201, s.userJSON(u))
}

// userChange is what an update does to a SCIM user.
type userChange struct {
	userName    *string
	externalID  *string
	displayName *string
	active      *bool
}

func (s *scimAPI) replaceUser(c *fiber.Ctx) error {
	var in userInput
	if err := json.Unmarshal(c.Body(), &in); err != nil {
		return s.fail(c, scimError(400, "invalidSyntax", "the body is not a SCIM User"))
	}
	ch := userChange{userName: in.UserName, externalID: in.ExternalID, displayName: in.display()}
	if in.Active != nil {
		v, ok := scimBool(in.Active)
		if !ok {
			return s.fail(c, scimError(400, "invalidValue", "active must be a boolean"))
		}
		ch.active = &v
	}
	return s.applyUser(c, ch)
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type patchBody struct {
	Operations []patchOp `json:"Operations"`
}

func (s *scimAPI) patchUser(c *fiber.Ctx) error {
	var body patchBody
	if err := json.Unmarshal(c.Body(), &body); err != nil || len(body.Operations) == 0 || len(body.Operations) > 100 {
		return s.fail(c, scimError(400, "invalidSyntax", "the body is not a SCIM PatchOp"))
	}
	var ch userChange
	set := func(path string, raw json.RawMessage) error {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return scimError(400, "invalidValue", "the value of "+path+" cannot be read")
		}
		str := func() *string {
			if x, ok := v.(string); ok {
				return &x
			}
			return nil
		}
		switch strings.ToLower(path) {
		case "active":
			b, ok := scimBool(v)
			if !ok {
				return scimError(400, "invalidValue", "active must be a boolean")
			}
			ch.active = &b
		case "username":
			ch.userName = str()
		case "externalid":
			ch.externalID = str()
		case "displayname", "name.formatted":
			if x := str(); x != nil {
				d := truncateRunes(strings.TrimSpace(*x), 200)
				ch.displayName = &d
			}
		}
		// Other attributes (title, phone numbers, the enterprise extension…)
		// are accepted and ignored: Guard Spec does not keep them.
		return nil
	}
	for _, op := range body.Operations {
		switch strings.ToLower(op.Op) {
		case "add", "replace":
		case "remove":
			continue // nothing Guard Spec keeps can be removed
		default:
			return s.fail(c, scimError(400, "invalidSyntax", "op must be add, replace or remove"))
		}
		if op.Path != "" {
			if err := set(op.Path, op.Value); err != nil {
				return s.fail(c, err)
			}
			continue
		}
		// No path: value is an object of attributes (Okta).
		var attrs map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &attrs); err != nil {
			return s.fail(c, scimError(400, "invalidValue", "an operation without a path needs an object value"))
		}
		for k, v := range attrs {
			if k == "name" {
				var n struct {
					Formatted string `json:"formatted"`
				}
				if json.Unmarshal(v, &n) == nil && n.Formatted != "" {
					b, _ := json.Marshal(n.Formatted)
					v, k = b, "name.formatted"
				}
			}
			if err := set(k, v); err != nil {
				return s.fail(c, err)
			}
		}
	}
	return s.applyUser(c, ch)
}

// applyUser updates a SCIM user and applies a change of active.
func (s *scimAPI) applyUser(c *fiber.Ctx, ch userChange) error {
	ctx := c.Context()
	org := scimOrg(c)
	if ch.userName != nil && (strings.TrimSpace(*ch.userName) == "" || len(*ch.userName) > scimNameMax) {
		return s.fail(c, scimError(400, "invalidValue", "userName must be 1 to 320 characters"))
	}
	if err := validExternalID(ch.externalID); err != nil {
		return s.fail(c, err)
	}
	var u scimUserRow
	var effect deactivation
	err := tenant.WithOrg(ctx, s.db, org, func(tx pgx.Tx) error {
		var err error
		u, err = s.loadUser(ctx, tx, org, c.Params("id"))
		if err != nil {
			return err
		}
		var created bool
		if err := tx.QueryRow(ctx, `SELECT created FROM scim_users WHERE id = $1 FOR UPDATE`, u.ID).Scan(&created); err != nil {
			return err
		}
		if ch.userName != nil {
			name := strings.TrimSpace(*ch.userName)
			if _, err := tx.Exec(ctx, `UPDATE scim_users SET user_name = $2 WHERE id = $1`, u.ID, name); err != nil {
				if isUniqueViolation(err) {
					return scimError(409, "uniqueness", "a user with this userName exists")
				}
				return err
			}
			// The account's email follows only for an account SCIM created:
			// an existing account keeps the email its owner signs in with.
			if e := strings.ToLower(name); created && validEmail(e) && e != u.Email {
				if _, err := tx.Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, u.UserID, e); err != nil {
					if isUniqueViolation(err) {
						return scimError(409, "uniqueness", "another account has this email")
					}
					return err
				}
			}
		}
		if ch.externalID != nil {
			if _, err := tx.Exec(ctx, `UPDATE scim_users SET external_id = NULLIF($2, '') WHERE id = $1`, u.ID, *ch.externalID); err != nil {
				return err
			}
		}
		if ch.displayName != nil && created {
			if _, err := tx.Exec(ctx, `UPDATE users SET display_name = NULLIF($2, '') WHERE id = $1`, u.UserID, *ch.displayName); err != nil {
				return err
			}
		}
		if ch.active != nil && *ch.active != u.Active {
			if *ch.active {
				err = s.reactivate(ctx, tx, org, u.ID)
			} else {
				effect, err = s.deactivate(ctx, tx, org, u.ID)
			}
			if err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE scim_users SET updated_at = NOW() WHERE id = $1`, u.ID); err != nil {
			return err
		}
		u, err = s.loadUser(ctx, tx, org, u.ID.String())
		return err
	})
	if err != nil {
		return s.fail(c, err)
	}
	if err := s.afterDeactivate(c, u.UserID, effect); err != nil {
		return s.fail(c, err)
	}
	if ch.active != nil {
		action := "scim.user_reactivated"
		if !*ch.active {
			action = "scim.user_deactivated"
		}
		if effect.done || *ch.active {
			s.activity(c, action, u.UserID.String(), map[string]any{"user_name": u.UserName,
				"keys_revoked": effect.keysRevoked, "sessions_revoked": effect.revokeSessions, "account_disabled": effect.disabled})
		}
	}
	s.activity(c, "scim.user_updated", u.UserID.String(), map[string]any{"user_name": u.UserName})
	return s.reply(c, 200, s.userJSON(u))
}

// deactivation is what a deactivation did inside its transaction; the
// sessions are revoked after it commits.
type deactivation struct {
	done           bool
	keysRevoked    int64
	revokeSessions bool
	disabled       bool
}

// deactivate removes the membership of SCIM user sid (keeping its role),
// revokes the user's API keys in the org when the org asks for it, and
// disables an account the org owns when the org is its only one.
func (s *scimAPI) deactivate(ctx context.Context, tx pgx.Tx, org, sid uuid.UUID) (deactivation, error) {
	var d deactivation
	var user uuid.UUID
	var created bool
	var email string
	if err := tx.QueryRow(ctx, `SELECT s.user_id, s.created, u.email FROM scim_users s JOIN users u ON u.id = s.user_id
		WHERE s.id = $1`, sid).Scan(&user, &created, &email); err != nil {
		return d, err
	}
	var role *string
	err := tx.QueryRow(ctx, `SELECT role::text FROM org_memberships WHERE org_id = $1 AND user_id = $2 FOR UPDATE`, org, user).
		Scan(&role)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return d, err
	}
	if role != nil && *role == string(auth.RoleOwner) {
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM org_memberships m JOIN users u ON u.id = m.user_id
			WHERE m.org_id = $1 AND m.role = 'owner' AND m.user_id <> $2 AND u.disabled_at IS NULL`, org, user).
			Scan(&others); err != nil {
			return d, err
		}
		if others == 0 {
			return d, scimError(409, "mutability", "this user is the organization's only owner; add another owner first")
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM project_memberships pm USING projects p
		WHERE pm.project_id = p.id AND p.org_id = $1 AND pm.user_id = $2`, org, user); err != nil {
		return d, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM org_memberships WHERE org_id = $1 AND user_id = $2`, org, user); err != nil {
		return d, err
	}
	keep := scimDefaultRole
	if role != nil {
		keep = *role
	}
	if _, err := tx.Exec(ctx, `UPDATE scim_users SET active = false, suspended_role = $2::org_role WHERE id = $1`, sid, keep); err != nil {
		return d, err
	}
	var revokeKeys bool
	err = tx.QueryRow(ctx, `SELECT scim_revoke_keys FROM org_security WHERE org_id = $1`, org).Scan(&revokeKeys)
	if errors.Is(err, pgx.ErrNoRows) {
		revokeKeys, err = true, nil
	}
	if err != nil {
		return d, err
	}
	if revokeKeys {
		tag, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at = NOW()
			WHERE org_id = $1 AND created_by = $2 AND revoked_at IS NULL`, org, user)
		if err != nil {
			return d, err
		}
		d.keysRevoked = tag.RowsAffected()
	}
	owned := created
	if !owned {
		if owned, err = orgClaims(ctx, s.db, org, email); err != nil {
			return d, err
		}
	}
	if owned {
		d.revokeSessions = true
		var others int
		if err := tx.QueryRow(ctx, `SELECT user_other_orgs($1, $2)`, user, org).Scan(&others); err != nil {
			return d, err
		}
		if others == 0 {
			var at time.Time
			err := tx.QueryRow(ctx, `UPDATE users SET disabled_at = NOW() WHERE id = $1 AND disabled_at IS NULL
				RETURNING disabled_at`, user).Scan(&at)
			switch {
			case errors.Is(err, pgx.ErrNoRows): // already disabled by someone else: theirs to undo
			case err != nil:
				return d, err
			default:
				d.disabled = true
				if _, err := tx.Exec(ctx, `UPDATE scim_users SET account_disabled_at = $2 WHERE id = $1`, sid, at); err != nil {
					return d, err
				}
			}
		}
	}
	d.done = true
	return d, nil
}

// afterDeactivate ends the sessions of a deactivated account the org owns;
// RequireRole already refuses the removed membership.
func (s *scimAPI) afterDeactivate(c *fiber.Ctx, user uuid.UUID, d deactivation) error {
	if !d.done {
		return nil
	}
	if d.revokeSessions {
		if _, err := s.sessions.RevokeAll(c.Context(), user, uuid.Nil); err != nil {
			return err
		}
	}
	s.sessions.Forget(user)
	return nil
}

// reactivate gives a SCIM user their membership back, with the role their
// groups map to; without a match, the default role when the org maps SCIM
// groups (the directory decides), else the role they had. An owner stays one.
func (s *scimAPI) reactivate(ctx context.Context, tx pgx.Tx, org, sid uuid.UUID) error {
	var user uuid.UUID
	var role *string
	var disabledAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT user_id, suspended_role::text, account_disabled_at FROM scim_users WHERE id = $1`, sid).
		Scan(&user, &role, &disabledAt); err != nil {
		return err
	}
	r := scimDefaultRole
	if role != nil {
		r = *role
	}
	if r != string(auth.RoleOwner) {
		mapped, ok, err := s.groupRole(ctx, tx, org, sid)
		if err != nil {
			return err
		}
		if ok {
			r = mapped
		} else if m, err := scimMapped(ctx, tx, org); err != nil {
			return err
		} else if m {
			r = scimDefaultRole
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, $3::org_role)
		ON CONFLICT DO NOTHING`, user, org, r); err != nil {
		return err
	}
	if disabledAt != nil {
		// Only the disabling this org's deactivation did: an administrator
		// who disabled the account since keeps it disabled.
		if _, err := tx.Exec(ctx, `UPDATE users SET disabled_at = NULL WHERE id = $1 AND disabled_at = $2`, user, *disabledAt); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE scim_users SET active = true, suspended_role = NULL, account_disabled_at = NULL WHERE id = $1`, sid)
	return err
}

func (s *scimAPI) deleteUser(c *fiber.Ctx) error {
	ctx := c.Context()
	org := scimOrg(c)
	var u scimUserRow
	var effect deactivation
	err := tenant.WithOrg(ctx, s.db, org, func(tx pgx.Tx) error {
		var err error
		if u, err = s.loadUser(ctx, tx, org, c.Params("id")); err != nil {
			return err
		}
		if u.Active {
			if effect, err = s.deactivate(ctx, tx, org, u.ID); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `DELETE FROM scim_users WHERE id = $1`, u.ID)
		return err
	})
	if err != nil {
		return s.fail(c, err)
	}
	if err := s.afterDeactivate(c, u.UserID, effect); err != nil {
		return s.fail(c, err)
	}
	s.activity(c, "scim.user_deleted", u.UserID.String(), map[string]any{"user_name": u.UserName,
		"keys_revoked": effect.keysRevoked, "account_disabled": effect.disabled})
	return c.SendStatus(204)
}

// ── Groups ───────────────────────────────────────────────────────────────────

type scimGroupRow struct {
	ID          uuid.UUID
	DisplayName string
	ExternalID  *string
	Created     time.Time
	Updated     time.Time
	Members     []scimRef
}

func (s *scimAPI) groupJSON(g scimGroupRow, withMembers bool) fiber.Map {
	m := fiber.Map{
		"schemas":     []string{scimGroupSchema},
		"id":          g.ID.String(),
		"displayName": g.DisplayName,
		"meta": fiber.Map{"resourceType": "Group", "created": g.Created.UTC().Format(time.RFC3339),
			"lastModified": g.Updated.UTC().Format(time.RFC3339), "location": s.base + "/Groups/" + g.ID.String()},
	}
	if withMembers {
		m["members"] = g.Members
		if g.Members == nil {
			m["members"] = []scimRef{}
		}
	}
	if g.ExternalID != nil {
		m["externalId"] = *g.ExternalID
	}
	return m
}

func (s *scimAPI) loadGroup(ctx context.Context, tx pgx.Tx, org uuid.UUID, id string, members bool) (scimGroupRow, error) {
	var g scimGroupRow
	gid, err := uuid.Parse(id)
	if err != nil {
		return g, scimError(404, "", "group not found")
	}
	err = tx.QueryRow(ctx, `SELECT id, display_name, external_id, created_at, updated_at FROM scim_groups
		WHERE org_id = $1 AND id = $2`, org, gid).Scan(&g.ID, &g.DisplayName, &g.ExternalID, &g.Created, &g.Updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, scimError(404, "", "group not found")
	}
	if err != nil || !members {
		return g, err
	}
	rows, err := tx.Query(ctx, `SELECT s.id::text, s.user_name FROM scim_group_members m JOIN scim_users s ON s.id = m.scim_user_id
		WHERE m.group_id = $1 ORDER BY s.user_name`, g.ID)
	if err != nil {
		return g, err
	}
	g.Members, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (scimRef, error) {
		var x scimRef
		err := r.Scan(&x.Value, &x.Display)
		x.Ref = s.base + "/Users/" + x.Value
		return x, err
	})
	return g, err
}

func excludesMembers(c *fiber.Ctx) bool {
	return strings.Contains(strings.ToLower(c.Query("excludedAttributes")), "members")
}

func (s *scimAPI) listGroups(c *fiber.Ctx) error {
	org := scimOrg(c)
	col, val, err := parseFilter(c.Query("filter"), map[string]string{
		"displayname": "lower(display_name) = lower($2)", "externalid": "external_id = $2", "id": "id::text = $2"})
	if err != nil {
		return s.fail(c, err)
	}
	start, count := paging(c)
	where := "org_id = $1"
	args := []any{org}
	if col != "" {
		where += " AND " + col
		args = append(args, val)
	}
	members := !excludesMembers(c)
	var total int
	var list []scimGroupRow
	err = tenant.WithOrg(c.Context(), s.db, org, func(tx pgx.Tx) error {
		if err := tx.QueryRow(c.Context(), `SELECT count(*) FROM scim_groups WHERE `+where, args...).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(), `SELECT id::text FROM scim_groups WHERE `+where+
			fmt.Sprintf(` ORDER BY created_at, id OFFSET %d LIMIT %d`, start-1, count), args...)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, id := range ids {
			g, err := s.loadGroup(c.Context(), tx, org, id, members)
			if err != nil {
				return err
			}
			list = append(list, g)
		}
		return nil
	})
	if err != nil {
		return s.fail(c, err)
	}
	res := make([]fiber.Map, 0, len(list))
	for _, g := range list {
		res = append(res, s.groupJSON(g, members))
	}
	return s.reply(c, 200, fiber.Map{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": start,
		"itemsPerPage": len(res), "Resources": res})
}

func (s *scimAPI) getGroup(c *fiber.Ctx) error {
	org := scimOrg(c)
	var g scimGroupRow
	err := tenant.WithOrg(c.Context(), s.db, org, func(tx pgx.Tx) error {
		var err error
		g, err = s.loadGroup(c.Context(), tx, org, c.Params("id"), !excludesMembers(c))
		return err
	})
	if err != nil {
		return s.fail(c, err)
	}
	return s.reply(c, 200, s.groupJSON(g, !excludesMembers(c)))
}

type scimGroupInput struct {
	DisplayName *string   `json:"displayName"`
	ExternalID  *string   `json:"externalId"`
	Members     []scimRef `json:"members"`
}

func validDisplayName(p *string) (string, error) {
	if p == nil || strings.TrimSpace(*p) == "" || len(*p) > scimDisplayMax {
		return "", scimError(400, "invalidValue", "displayName must be 1 to 256 characters")
	}
	return strings.TrimSpace(*p), nil
}

// memberIDs reads member references, which must be users of the org.
func memberIDs(ctx context.Context, tx pgx.Tx, org uuid.UUID, refs []scimRef) ([]uuid.UUID, error) {
	if len(refs) > scimMaxMembers {
		return nil, scimError(400, "tooMany", fmt.Sprintf("at most %d members per request", scimMaxMembers))
	}
	ids := make([]uuid.UUID, 0, len(refs))
	for _, r := range refs {
		id, err := uuid.Parse(r.Value)
		if err != nil {
			return nil, scimError(400, "invalidValue", "member "+r.Value+" is not a user of this organization")
		}
		ids = append(ids, id)
	}
	var found int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM scim_users WHERE org_id = $1 AND id = ANY($2)`, org, ids).
		Scan(&found); err != nil {
		return nil, err
	}
	if found != len(slices.Compact(slices.SortedFunc(slices.Values(ids), func(a, b uuid.UUID) int {
		return strings.Compare(a.String(), b.String())
	}))) {
		return nil, scimError(400, "invalidValue", "a member is not a user of this organization")
	}
	return ids, nil
}

func (s *scimAPI) createGroup(c *fiber.Ctx) error {
	ctx := c.Context()
	org := scimOrg(c)
	var in scimGroupInput
	if err := json.Unmarshal(c.Body(), &in); err != nil {
		return s.fail(c, scimError(400, "invalidSyntax", "the body is not a SCIM Group"))
	}
	name, err := validDisplayName(in.DisplayName)
	if err != nil {
		return s.fail(c, err)
	}
	if err := validExternalID(in.ExternalID); err != nil {
		return s.fail(c, err)
	}
	var g scimGroupRow
	err = tenant.WithOrg(ctx, s.db, org, func(tx pgx.Tx) error {
		ids, err := memberIDs(ctx, tx, org, in.Members)
		if err != nil {
			return err
		}
		var gid uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO scim_groups (org_id, display_name, external_id) VALUES ($1, $2, $3) RETURNING id`,
			org, name, in.ExternalID).Scan(&gid); err != nil {
			if isUniqueViolation(err) {
				return scimError(409, "uniqueness", "a group with this displayName exists")
			}
			return err
		}
		if err := s.addMembers(ctx, tx, org, gid, ids); err != nil {
			return err
		}
		g, err = s.loadGroup(ctx, tx, org, gid.String(), true)
		return err
	})
	if err != nil {
		return s.fail(c, err)
	}
	s.activity(c, "scim.group_created", g.DisplayName, map[string]any{"group_id": g.ID, "members": len(g.Members)})
	c.Set(fiber.HeaderLocation, s.base+"/Groups/"+g.ID.String())
	return s.reply(c, 201, s.groupJSON(g, true))
}

func (s *scimAPI) addMembers(ctx context.Context, tx pgx.Tx, org, gid uuid.UUID, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO scim_group_members (group_id, scim_user_id, org_id)
		SELECT $1, unnest($2::uuid[]), $3 ON CONFLICT DO NOTHING`, gid, ids, org); err != nil {
		return err
	}
	return s.syncRoles(ctx, tx, org, ids)
}

func (s *scimAPI) removeMembers(ctx context.Context, tx pgx.Tx, org, gid uuid.UUID, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id = $1 AND scim_user_id = ANY($2)`, gid, ids); err != nil {
		return err
	}
	return s.syncRoles(ctx, tx, org, ids)
}

// groupRole is the highest role mapped to a group of SCIM user sid.
func (s *scimAPI) groupRole(ctx context.Context, tx pgx.Tx, org, sid uuid.UUID) (string, bool, error) {
	rows, err := tx.Query(ctx, `SELECT g.display_name, COALESCE(g.external_id, '') FROM scim_group_members m
		JOIN scim_groups g ON g.id = m.group_id WHERE m.scim_user_id = $1`, sid)
	if err != nil {
		return "", false, err
	}
	var keys []string
	for rows.Next() {
		var name, ext string
		if err := rows.Scan(&name, &ext); err != nil {
			rows.Close()
			return "", false, err
		}
		keys = append(keys, name)
		if ext != "" {
			keys = append(keys, ext)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(keys) == 0 {
		return "", false, err
	}
	return mappedRole(ctx, tx, org, nil, keys)
}

// syncRoles sets the role of active SCIM users to the highest role their
// groups map to. Once the org maps SCIM groups to roles, the directory
// decides: a user whose groups map to nothing (for example after leaving
// the admins group) falls back to the default role, so a removal in the IdP
// takes the access away. Without any SCIM mapping roles are left alone. An
// owner is never changed.
func (s *scimAPI) syncRoles(ctx context.Context, tx pgx.Tx, org uuid.UUID, sids []uuid.UUID) error {
	if len(sids) == 0 {
		return nil
	}
	mapped, err := scimMapped(ctx, tx, org)
	if err != nil || !mapped {
		return err
	}
	for _, sid := range sids {
		role, ok, err := s.groupRole(ctx, tx, org, sid)
		if err != nil {
			return err
		}
		if !ok {
			role = scimDefaultRole
		}
		var user uuid.UUID
		var old string
		err = tx.QueryRow(ctx, `UPDATE org_memberships m SET role = $3::org_role
			FROM scim_users s, (SELECT user_id, role FROM org_memberships WHERE org_id = $2 FOR UPDATE) o
			WHERE s.id = $1 AND s.active AND m.user_id = s.user_id AND m.org_id = $2 AND o.user_id = m.user_id
			  AND m.role <> 'owner' AND m.role <> $3::org_role
			RETURNING m.user_id, o.role::text`, sid, org, role).Scan(&user, &old)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		writeActivity(ctx, s.db, activityEntry{Org: &org, Action: "member.role_from_group", Target: user.String(),
			Details: map[string]any{"from": old, "to": role, "source": "scim"}})
	}
	return nil
}

// scimMapped reports whether the org maps any SCIM group to a role.
func scimMapped(ctx context.Context, tx pgx.Tx, org uuid.UUID) (bool, error) {
	var mapped bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM org_group_roles WHERE org_id = $1 AND provider_id IS NULL)`,
		org).Scan(&mapped)
	return mapped, err
}

func (s *scimAPI) groupMemberIDs(ctx context.Context, tx pgx.Tx, gid uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT scim_user_id FROM scim_group_members WHERE group_id = $1`, gid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func (s *scimAPI) replaceGroup(c *fiber.Ctx) error {
	ctx := c.Context()
	org := scimOrg(c)
	var in scimGroupInput
	if err := json.Unmarshal(c.Body(), &in); err != nil {
		return s.fail(c, scimError(400, "invalidSyntax", "the body is not a SCIM Group"))
	}
	name, err := validDisplayName(in.DisplayName)
	if err != nil {
		return s.fail(c, err)
	}
	if err := validExternalID(in.ExternalID); err != nil {
		return s.fail(c, err)
	}
	var g scimGroupRow
	err = tenant.WithOrg(ctx, s.db, org, func(tx pgx.Tx) error {
		cur, err := s.loadGroup(ctx, tx, org, c.Params("id"), false)
		if err != nil {
			return err
		}
		ids, err := memberIDs(ctx, tx, org, in.Members)
		if err != nil {
			return err
		}
		if err := s.renameGroup(ctx, tx, org, cur.ID, &name, in.ExternalID); err != nil {
			return err
		}
		old, err := s.groupMemberIDs(ctx, tx, cur.ID)
		if err != nil {
			return err
		}
		if err := s.removeMembers(ctx, tx, org, cur.ID, old); err != nil {
			return err
		}
		if err := s.addMembers(ctx, tx, org, cur.ID, ids); err != nil {
			return err
		}
		g, err = s.loadGroup(ctx, tx, org, cur.ID.String(), true)
		return err
	})
	if err != nil {
		return s.fail(c, err)
	}
	s.activity(c, "scim.group_updated", g.DisplayName, map[string]any{"group_id": g.ID, "members": len(g.Members)})
	return s.reply(c, 200, s.groupJSON(g, true))
}

// renameGroup changes the name or external id; the roles of its members
// follow the new name.
func (s *scimAPI) renameGroup(ctx context.Context, tx pgx.Tx, org, gid uuid.UUID, name, ext *string) error {
	if name == nil && ext == nil {
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE scim_groups SET display_name = COALESCE($2, display_name),
		external_id = CASE WHEN $3::text IS NULL THEN external_id ELSE NULLIF($3, '') END, updated_at = NOW() WHERE id = $1`,
		gid, name, ext); err != nil {
		if isUniqueViolation(err) {
			return scimError(409, "uniqueness", "a group with this displayName exists")
		}
		return err
	}
	ids, err := s.groupMemberIDs(ctx, tx, gid)
	if err != nil {
		return err
	}
	return s.syncRoles(ctx, tx, org, ids)
}

// memberFilterRe reads members[value eq "<id>"] (Okta's remove).
var memberFilterRe = regexp.MustCompile(`(?i)^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$`)

func (s *scimAPI) patchGroup(c *fiber.Ctx) error {
	ctx := c.Context()
	org := scimOrg(c)
	var body patchBody
	if err := json.Unmarshal(c.Body(), &body); err != nil || len(body.Operations) == 0 || len(body.Operations) > 100 {
		return s.fail(c, scimError(400, "invalidSyntax", "the body is not a SCIM PatchOp"))
	}
	var g scimGroupRow
	err := tenant.WithOrg(ctx, s.db, org, func(tx pgx.Tx) error {
		cur, err := s.loadGroup(ctx, tx, org, c.Params("id"), false)
		if err != nil {
			return err
		}
		refs := func(raw json.RawMessage) ([]uuid.UUID, error) {
			var list []scimRef
			if len(raw) == 0 || string(raw) == "null" {
				return nil, nil
			}
			if err := json.Unmarshal(raw, &list); err != nil {
				return nil, scimError(400, "invalidValue", "members must be a list of {value}")
			}
			return memberIDs(ctx, tx, org, list)
		}
		for _, op := range body.Operations {
			kind := strings.ToLower(op.Op)
			path := strings.TrimSpace(op.Path)
			switch {
			case kind != "add" && kind != "replace" && kind != "remove":
				return scimError(400, "invalidSyntax", "op must be add, replace or remove")
			case strings.EqualFold(path, "members"):
				ids, err := refs(op.Value)
				if err != nil {
					return err
				}
				switch kind {
				case "add":
					err = s.addMembers(ctx, tx, org, cur.ID, ids)
				case "remove":
					if len(ids) == 0 { // remove all
						if ids, err = s.groupMemberIDs(ctx, tx, cur.ID); err != nil {
							return err
						}
					}
					err = s.removeMembers(ctx, tx, org, cur.ID, ids)
				case "replace":
					old, err2 := s.groupMemberIDs(ctx, tx, cur.ID)
					if err2 != nil {
						return err2
					}
					if err = s.removeMembers(ctx, tx, org, cur.ID, old); err == nil {
						err = s.addMembers(ctx, tx, org, cur.ID, ids)
					}
				}
				if err != nil {
					return err
				}
			case memberFilterRe.MatchString(path) && kind == "remove":
				id, err := uuid.Parse(memberFilterRe.FindStringSubmatch(path)[1])
				if err != nil {
					return scimError(400, "invalidValue", "the member id is not valid")
				}
				if err := s.removeMembers(ctx, tx, org, cur.ID, []uuid.UUID{id}); err != nil {
					return err
				}
			case strings.EqualFold(path, "displayName") || strings.EqualFold(path, "externalId") || path == "":
				var name, ext *string
				if path == "" {
					var v struct {
						DisplayName *string   `json:"displayName"`
						ExternalID  *string   `json:"externalId"`
						Members     []scimRef `json:"members"`
					}
					if err := json.Unmarshal(op.Value, &v); err != nil {
						return scimError(400, "invalidValue", "an operation without a path needs an object value")
					}
					name, ext = v.DisplayName, v.ExternalID
					if v.Members != nil {
						ids, err := memberIDs(ctx, tx, org, v.Members)
						if err != nil {
							return err
						}
						if kind == "replace" {
							old, err := s.groupMemberIDs(ctx, tx, cur.ID)
							if err != nil {
								return err
							}
							if err := s.removeMembers(ctx, tx, org, cur.ID, old); err != nil {
								return err
							}
						}
						if err := s.addMembers(ctx, tx, org, cur.ID, ids); err != nil {
							return err
						}
					}
				} else {
					var x string
					if err := json.Unmarshal(op.Value, &x); err != nil {
						return scimError(400, "invalidValue", path+" must be a string")
					}
					if strings.EqualFold(path, "displayName") {
						name = &x
					} else {
						ext = &x
					}
				}
				if name != nil {
					n, err := validDisplayName(name)
					if err != nil {
						return err
					}
					name = &n
				}
				if err := validExternalID(ext); err != nil {
					return err
				}
				if err := s.renameGroup(ctx, tx, org, cur.ID, name, ext); err != nil {
					return err
				}
			default:
				return scimError(400, "invalidPath", "path "+path+" is not supported")
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE scim_groups SET updated_at = NOW() WHERE id = $1`, cur.ID); err != nil {
			return err
		}
		g, err = s.loadGroup(ctx, tx, org, cur.ID.String(), true)
		return err
	})
	if err != nil {
		return s.fail(c, err)
	}
	s.activity(c, "scim.group_updated", g.DisplayName, map[string]any{"group_id": g.ID, "members": len(g.Members)})
	if excludesMembers(c) || c.Query("attributes") != "" {
		return c.SendStatus(204)
	}
	return s.reply(c, 200, s.groupJSON(g, true))
}

func (s *scimAPI) deleteGroup(c *fiber.Ctx) error {
	ctx := c.Context()
	org := scimOrg(c)
	var g scimGroupRow
	err := tenant.WithOrg(ctx, s.db, org, func(tx pgx.Tx) error {
		var err error
		if g, err = s.loadGroup(ctx, tx, org, c.Params("id"), false); err != nil {
			return err
		}
		ids, err := s.groupMemberIDs(ctx, tx, g.ID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scim_groups WHERE id = $1`, g.ID); err != nil {
			return err
		}
		return s.syncRoles(ctx, tx, org, ids)
	})
	if err != nil {
		return s.fail(c, err)
	}
	s.activity(c, "scim.group_deleted", g.DisplayName, map[string]any{"group_id": g.ID})
	return c.SendStatus(204)
}

// ── Organization admin: tokens and group roles ───────────────────────────────

type scimTokenRow struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

func listSCIMTokens(db *pgxpool.Pool, base string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var list []scimTokenRow
		var users, groups int
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(), `SELECT id, name, token_prefix, created_at, last_used_at, expires_at, revoked_at
				FROM scim_tokens WHERE org_id = $1 ORDER BY created_at DESC, id`, org)
			if err != nil {
				return err
			}
			list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (scimTokenRow, error) {
				var t scimTokenRow
				err := r.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt, &t.RevokedAt)
				return t, err
			})
			if err != nil {
				return err
			}
			return tx.QueryRow(c.Context(), `SELECT (SELECT count(*) FROM scim_users WHERE org_id = $1),
				(SELECT count(*) FROM scim_groups WHERE org_id = $1)`, org).Scan(&users, &groups)
		})
		if err != nil {
			return serverError(c, err)
		}
		if list == nil {
			list = []scimTokenRow{}
		}
		return c.JSON(fiber.Map{"items": list, "base_url": base, "users": users, "groups": groups})
	}
}

func createSCIMToken(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			Name      string     `json:"name"`
			ExpiresAt *time.Time `json:"expires_at"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" || len([]rune(req.Name)) > 100 {
			return c.Status(400).JSON(fiber.Map{"error": "name must be 1 to 100 characters"})
		}
		if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
			return c.Status(400).JSON(fiber.Map{"error": "expires_at must be in the future"})
		}
		secret, err := randomToken()
		if err != nil {
			return serverError(c, err)
		}
		tok := scimTokenPrefix + secret
		var t scimTokenRow
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var n int
			if err := tx.QueryRow(c.Context(), `SELECT count(*) FROM scim_tokens WHERE org_id = $1 AND revoked_at IS NULL`, org).
				Scan(&n); err != nil {
				return err
			}
			if n >= maxSCIMTokens {
				return errTooMany
			}
			return tx.QueryRow(c.Context(), `INSERT INTO scim_tokens (org_id, name, token_hash, token_prefix, created_by, expires_at)
				VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, token_prefix, created_at, last_used_at, expires_at, revoked_at`,
				org, req.Name, tenant.HashKey(tok), tok[:12], auth.UserID(c), req.ExpiresAt).
				Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt, &t.RevokedAt)
		})
		if errors.Is(err, errTooMany) {
			return c.Status(409).JSON(fiber.Map{"error": fmt.Sprintf("at most %d active SCIM tokens; revoke one first", maxSCIMTokens)})
		}
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "scim.token_created", t.Name, map[string]any{"id": t.ID})
		// The token is shown once.
		return c.Status(201).JSON(fiber.Map{"token": tok, "item": t})
	}
}

var errTooMany = errors.New("too many")

func revokeSCIMToken(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		tid, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		var name string
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(), `UPDATE scim_tokens SET revoked_at = COALESCE(revoked_at, NOW())
				WHERE org_id = $1 AND id = $2 RETURNING name`, org, tid).Scan(&name)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "scim.token_revoked", name, map[string]any{"id": tid})
		return c.SendStatus(204)
	}
}

type groupRoleRow struct {
	ID         uuid.UUID  `json:"id,omitempty"`
	ProviderID *uuid.UUID `json:"provider_id"`
	GroupKey   string     `json:"group_key"`
	Role       string     `json:"role"`
}

func loadGroupRoles(ctx context.Context, db *pgxpool.Pool, org uuid.UUID) ([]groupRoleRow, error) {
	var list []groupRoleRow
	err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, provider_id, group_key, role::text FROM org_group_roles WHERE org_id = $1
			ORDER BY provider_id NULLS FIRST, lower(group_key)`, org)
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (groupRoleRow, error) {
			var g groupRoleRow
			return g, r.Scan(&g.ID, &g.ProviderID, &g.GroupKey, &g.Role)
		})
		return err
	})
	if list == nil {
		list = []groupRoleRow{}
	}
	return list, err
}

func getGroupRoles(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		list, err := loadGroupRoles(c.Context(), db, orgID(c))
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"items": list})
	}
}

// putGroupRoles replaces the org's group mappings. A SAML mapping names an
// SAML provider (a disabled one's mappings apply again once it is enabled);
// roles are viewer, member or admin.
func putGroupRoles(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			Items []groupRoleRow `json:"items"`
		}
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if len(req.Items) > 100 {
			return c.Status(400).JSON(fiber.Map{"error": "at most 100 group mappings"})
		}
		seen := map[string]bool{}
		for i := range req.Items {
			g := &req.Items[i]
			g.GroupKey = strings.TrimSpace(g.GroupKey)
			if g.GroupKey == "" || len(g.GroupKey) > 256 {
				return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("items[%d]: group_key must be 1 to 256 characters", i)})
			}
			if g.Role != "viewer" && g.Role != "member" && g.Role != "admin" {
				return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("items[%d]: role must be viewer, member or admin", i)})
			}
			if g.ProviderID != nil {
				var typ string
				err := db.QueryRow(c.Context(), `SELECT type FROM identity_providers WHERE id = $1`, *g.ProviderID).Scan(&typ)
				if errors.Is(err, pgx.ErrNoRows) || (err == nil && typ != "saml") {
					return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("items[%d]: provider_id must name a SAML provider", i)})
				}
				if err != nil {
					return serverError(c, err)
				}
			}
			key := strings.ToLower(g.GroupKey)
			if g.ProviderID != nil {
				key = g.ProviderID.String() + "/" + key
			}
			if seen[key] {
				return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("items[%d]: %s is listed twice", i, g.GroupKey)})
			}
			seen[key] = true
		}
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if _, err := tx.Exec(c.Context(), `DELETE FROM org_group_roles WHERE org_id = $1`, org); err != nil {
				return err
			}
			for _, g := range req.Items {
				if _, err := tx.Exec(c.Context(), `INSERT INTO org_group_roles (org_id, provider_id, group_key, role)
					VALUES ($1, $2, $3, $4::org_role)`, org, g.ProviderID, g.GroupKey, g.Role); err != nil {
					return err
				}
			}
			// SCIM users take the new mappings at once.
			rows, err := tx.Query(c.Context(), `SELECT id FROM scim_users WHERE org_id = $1 AND active`, org)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			if err != nil {
				return err
			}
			return (&scimAPI{db: db}).syncRoles(c.Context(), tx, org, ids)
		})
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "scim.group_roles_updated", "organization", map[string]any{"count": len(req.Items)})
		list, err := loadGroupRoles(c.Context(), db, org)
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"items": list})
	}
}
