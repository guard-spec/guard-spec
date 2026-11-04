package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/config"
	"github.com/giaplee/guard-spec/internal/policy"
	"github.com/giaplee/guard-spec/internal/proxy"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Upstreams are the named LLM APIs an org's requests can be routed to
// (migration 011). The gateway reads the key from the variable api_key_env
// names; no secret is stored here or returned.

// keyEnvRe limits api_key_env to variables meant for upstream keys, so that an
// org admin cannot make the gateway send another variable (JWT_SECRET) upstream.
var keyEnvRe = config.UpstreamKeyVarRe

const (
	defaultTimeoutMs = 300_000 // proxy.DefaultTimeout
	minTimeoutMs     = 1_000
	maxTimeoutMs     = 600_000
	maxModelLen      = 256
)

type upstream struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	BaseURL   string    `json:"base_url"`
	Model     string    `json:"model"`
	APIKeyEnv string    `json:"api_key_env"`
	TimeoutMs int       `json:"timeout_ms"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// validate checks the fields an admin sets; a zero timeout becomes the default.
func (u *upstream) validate() error {
	if !policy.ValidUpstreamName(u.Name) {
		return errors.New("name must be 1-63 lowercase letters, digits and dashes, starting with a letter or digit")
	}
	if err := proxy.ValidateBaseURL(u.BaseURL); err != nil {
		return fmt.Errorf("base_url: %w", err)
	}
	if len(u.Model) > maxModelLen || strings.IndexFunc(u.Model, unicode.IsControl) >= 0 {
		return fmt.Errorf("model must be at most %d characters without control characters", maxModelLen)
	}
	if u.APIKeyEnv != "" && !keyEnvRe.MatchString(u.APIKeyEnv) {
		return errors.New("api_key_env must match ^UPSTREAM_KEY_[A-Z0-9_]{1,64}$")
	}
	if u.TimeoutMs == 0 {
		u.TimeoutMs = defaultTimeoutMs
	}
	if u.TimeoutMs < minTimeoutMs || u.TimeoutMs > maxTimeoutMs {
		return fmt.Errorf("timeout_ms must be between %d and %d", minTimeoutMs, maxTimeoutMs)
	}
	return nil
}

const upstreamSelect = `SELECT id, name, base_url, model, COALESCE(api_key_env, ''), timeout_ms, enabled, created_at, updated_at
	FROM upstreams`

func scanUpstreamRow(row pgx.Row) (upstream, error) {
	var u upstream
	err := row.Scan(&u.ID, &u.Name, &u.BaseURL, &u.Model, &u.APIKeyEnv, &u.TimeoutMs, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func loadUpstreams(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]upstream, error) {
	rows, err := tx.Query(ctx, upstreamSelect+` WHERE org_id = $1 ORDER BY created_at, name`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []upstream{}
	for rows.Next() {
		u, err := scanUpstreamRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func listUpstreams(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var list []upstream
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			list, err = loadUpstreams(c.Context(), tx, org)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"data": list})
	}
}

func createUpstream(db *pgxpool.Pool, settings *appSettings) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var u upstream
		if err := json.Unmarshal(c.Body(), &u); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		u.Enabled = true
		var enabled struct {
			Enabled *bool `json:"enabled"`
		}
		_ = json.Unmarshal(c.Body(), &enabled)
		if enabled.Enabled != nil {
			u.Enabled = *enabled.Enabled
		}
		if err := u.validate(); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if err := settings.keyOrgs.Check(u.APIKeyEnv, org); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			u, err = scanUpstreamRow(tx.QueryRow(c.Context(),
				`INSERT INTO upstreams (org_id, name, base_url, model, api_key_env, timeout_ms, enabled)
				 VALUES ($1, $2, $3, $4, $5, $6, $7)
				 RETURNING id, name, base_url, model, COALESCE(api_key_env, ''), timeout_ms, enabled, created_at, updated_at`,
				org, u.Name, u.BaseURL, u.Model, nullString(u.APIKeyEnv), u.TimeoutMs, u.Enabled))
			return err
		})
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "an upstream with this name already exists"})
		}
		if err != nil {
			return serverError(c, err)
		}
		slog.Info("upstream created", "org", org, "upstream", u.Name, "by", auth.UserID(c))
		return c.Status(201).JSON(u)
	}
}

// upstreamPatch is a PUT body: absent fields keep their value.
type upstreamPatch struct {
	Name      *string `json:"name"`
	BaseURL   *string `json:"base_url"`
	Model     *string `json:"model"`
	APIKeyEnv *string `json:"api_key_env"`
	TimeoutMs *int    `json:"timeout_ms"`
	Enabled   *bool   `json:"enabled"`
}

func (p upstreamPatch) apply(u *upstream) {
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&u.Name, p.Name)
	set(&u.BaseURL, p.BaseURL)
	set(&u.Model, p.Model)
	set(&u.APIKeyEnv, p.APIKeyEnv)
	if p.TimeoutMs != nil {
		u.TimeoutMs = *p.TimeoutMs
	}
	if p.Enabled != nil {
		u.Enabled = *p.Enabled
	}
}

var errUpstreamNotFound = errors.New("upstream not found")

// upstreamInUse is a 409: the upstream is named by a rule or a default.
type upstreamInUse struct{ refs []upstreamRef }

func (e *upstreamInUse) Error() string { return "upstream is in use" }

type upstreamRef struct {
	Kind      string     `json:"kind"` // rule, org_default or project_default
	PolicyID  *uuid.UUID `json:"policy_id,omitempty"`
	Policy    string     `json:"policy,omitempty"`
	RuleID    string     `json:"rule_id,omitempty"`
	Rule      string     `json:"rule,omitempty"`
	ProjectID *uuid.UUID `json:"project_id,omitempty"`
	Project   string     `json:"project,omitempty"`
}

func (r upstreamRef) String() string {
	switch r.Kind {
	case "rule":
		return fmt.Sprintf("policy %q rule %q", r.Policy, r.Rule)
	case "org_default":
		return "the organization default"
	default:
		return fmt.Sprintf("the default of project %q", r.Project)
	}
}

func inUseResponse(c *fiber.Ctx, name string, refs []upstreamRef) error {
	names := make([]string, len(refs))
	for i, r := range refs {
		names[i] = r.String()
	}
	return c.Status(fiber.StatusConflict).JSON(fiber.Map{
		"error":      fmt.Sprintf("upstream %q is used by %s", name, strings.Join(names, ", ")),
		"references": refs,
	})
}

// upstreamRefs lists the rules (by name) and defaults (by id) that use an upstream.
func upstreamRefs(ctx context.Context, tx pgx.Tx, org uuid.UUID, id uuid.UUID, name string) ([]upstreamRef, error) {
	refs := []upstreamRef{}
	rows, err := tx.Query(ctx,
		`SELECT p.id, p.name, COALESCE(r->>'id', ''), COALESCE(r->>'name', '')
		 FROM policies p, jsonb_array_elements(CASE WHEN jsonb_typeof(p.rules) = 'array' THEN p.rules ELSE '[]'::jsonb END) r
		 WHERE p.org_id = $1 AND r->>'action' = 'route' AND r->>'route_target' = $2
		 ORDER BY p.created_at, p.id`, org, name)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ref upstreamRef
		var pid uuid.UUID
		if err := rows.Scan(&pid, &ref.Policy, &ref.RuleID, &ref.Rule); err != nil {
			rows.Close()
			return nil, err
		}
		ref.Kind, ref.PolicyID = "rule", &pid
		refs = append(refs, ref)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var orgDefault bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1 AND default_upstream_id = $2)`,
		org, id).Scan(&orgDefault); err != nil {
		return nil, err
	}
	if orgDefault {
		refs = append(refs, upstreamRef{Kind: "org_default"})
	}
	rows, err = tx.Query(ctx, `SELECT id, slug FROM projects WHERE org_id = $1 AND default_upstream_id = $2 ORDER BY slug`, org, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var pid uuid.UUID
		var slug string
		if err := rows.Scan(&pid, &slug); err != nil {
			return nil, err
		}
		refs = append(refs, upstreamRef{Kind: "project_default", ProjectID: &pid, Project: slug})
	}
	return refs, rows.Err()
}

// lockUpstream reads an upstream FOR UPDATE: a policy save that names it takes
// a share lock (checkRouteTargets), so a rename or delete and a save that
// references the old name cannot both succeed.
func lockUpstream(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (upstream, error) {
	u, err := scanUpstreamRow(tx.QueryRow(ctx, upstreamSelect+` WHERE id = $1 AND org_id = $2 FOR UPDATE`, id, org))
	if errors.Is(err, pgx.ErrNoRows) {
		return u, errUpstreamNotFound
	}
	return u, err
}

func updateUpstream(db *pgxpool.Pool, settings *appSettings) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid upstream id"})
		}
		var patch upstreamPatch
		if err := json.Unmarshal(c.Body(), &patch); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		var u upstream
		var oldName string
		var invalid error
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			if u, err = lockUpstream(c.Context(), tx, org, id); err != nil {
				return err
			}
			oldName = u.Name
			patch.apply(&u)
			if invalid = u.validate(); invalid != nil {
				return invalid
			}
			// The key goes where base_url points: changing either needs the
			// allowlist. Other changes (disabling, say) do not, so that an
			// upstream left over from a narrower allowlist can still be managed.
			if patch.APIKeyEnv != nil || patch.BaseURL != nil {
				if invalid = settings.keyOrgs.Check(u.APIKeyEnv, org); invalid != nil {
					return invalid
				}
			}
			if u.Name != oldName {
				refs, err := upstreamRefs(c.Context(), tx, org, id, oldName)
				if err != nil {
					return err
				}
				// Defaults name the upstream by id, so only rules hold the name.
				var rules []upstreamRef
				for _, r := range refs {
					if r.Kind == "rule" {
						rules = append(rules, r)
					}
				}
				if len(rules) > 0 {
					return &upstreamInUse{refs: rules}
				}
			}
			u, err = scanUpstreamRow(tx.QueryRow(c.Context(),
				`UPDATE upstreams SET name = $3, base_url = $4, model = $5, api_key_env = $6, timeout_ms = $7,
				   enabled = $8, updated_at = NOW()
				 WHERE id = $1 AND org_id = $2
				 RETURNING id, name, base_url, model, COALESCE(api_key_env, ''), timeout_ms, enabled, created_at, updated_at`,
				id, org, u.Name, u.BaseURL, u.Model, nullString(u.APIKeyEnv), u.TimeoutMs, u.Enabled))
			return err
		})
		var inUse *upstreamInUse
		switch {
		case errors.Is(err, errUpstreamNotFound):
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		case invalid != nil:
			return c.Status(400).JSON(fiber.Map{"error": invalid.Error()})
		case errors.As(err, &inUse):
			return inUseResponse(c, oldName, inUse.refs)
		case isUniqueViolation(err):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "an upstream with this name already exists"})
		case err != nil:
			return serverError(c, err)
		}
		slog.Info("upstream updated", "org", org, "upstream", u.Name, "enabled", u.Enabled, "by", auth.UserID(c))
		return c.JSON(u)
	}
}

func deleteUpstream(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid upstream id"})
		}
		var name string
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			u, err := lockUpstream(c.Context(), tx, org, id)
			if err != nil {
				return err
			}
			name = u.Name
			refs, err := upstreamRefs(c.Context(), tx, org, id, u.Name)
			if err != nil {
				return err
			}
			if len(refs) > 0 {
				return &upstreamInUse{refs: refs}
			}
			_, err = tx.Exec(c.Context(), `DELETE FROM upstreams WHERE id = $1 AND org_id = $2`, id, org)
			return err
		})
		var inUse *upstreamInUse
		switch {
		case errors.Is(err, errUpstreamNotFound):
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		case errors.As(err, &inUse):
			return inUseResponse(c, name, inUse.refs)
		case isForeignKeyViolation(err):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "upstream is in use"})
		case err != nil:
			return serverError(c, err)
		}
		slog.Info("upstream deleted", "org", org, "upstream", name, "by", auth.UserID(c))
		return c.Status(204).Send(nil)
	}
}

var errUnknownUpstream = errors.New("upstream_id does not name an upstream of this organization")

// defaultUpstreamBody reads {"upstream_id": "uuid" | null}; the key is required.
func defaultUpstreamBody(c *fiber.Ctx) (*uuid.UUID, error) {
	var req struct {
		UpstreamID optUUID `json:"upstream_id"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return nil, err
	}
	if !req.UpstreamID.Set {
		return nil, errors.New("upstream_id (an id or null) is required")
	}
	return req.UpstreamID.Value, nil
}

// checkUpstream verifies that id is an upstream of org, with a share lock so
// that it cannot be deleted before the transaction commits.
func checkUpstream(ctx context.Context, tx pgx.Tx, org uuid.UUID, id *uuid.UUID) error {
	if id == nil {
		return nil
	}
	var found uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM upstreams WHERE id = $1 AND org_id = $2 FOR SHARE`, *id, org).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return errUnknownUpstream
	}
	return err
}

func putOrgDefaultUpstream(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := defaultUpstreamBody(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := checkUpstream(c.Context(), tx, org, id); err != nil {
				return err
			}
			_, err := tx.Exec(c.Context(),
				`UPDATE organizations SET default_upstream_id = $1, updated_at = NOW() WHERE id = $2`, id, org)
			return err
		})
		if errors.Is(err, errUnknownUpstream) {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if err != nil {
			return serverError(c, err)
		}
		slog.Info("org default upstream changed", "org", org, "upstream", id, "by", auth.UserID(c))
		return c.JSON(fiber.Map{"id": org, "default_upstream_id": id})
	}
}

func putProjectDefaultUpstream(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		project, err := uuid.Parse(c.Params("projectId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid project id"})
		}
		id, err := defaultUpstreamBody(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		var updated int64
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := checkUpstream(c.Context(), tx, org, id); err != nil {
				return err
			}
			tag, err := tx.Exec(c.Context(),
				`UPDATE projects SET default_upstream_id = $1 WHERE id = $2 AND org_id = $3`, id, project, org)
			updated = tag.RowsAffected()
			return err
		})
		if errors.Is(err, errUnknownUpstream) {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if err != nil {
			return serverError(c, err)
		}
		if updated == 0 {
			return c.Status(404).JSON(fiber.Map{"error": "project not found"})
		}
		slog.Info("project default upstream changed", "org", org, "project", project, "upstream", id, "by", auth.UserID(c))
		return c.JSON(fiber.Map{"id": project, "default_upstream_id": id})
	}
}

// unknownTargetError is a route rule naming an upstream the org does not have.
type unknownTargetError struct{ name string }

func (e *unknownTargetError) Error() string {
	return fmt.Sprintf("route_target %q does not name an upstream of this organization", e.name)
}

// checkRouteTargets verifies that every route target names an upstream of
// org, and share-locks those upstreams until the policy is saved.
func checkRouteTargets(ctx context.Context, tx pgx.Tx, org uuid.UUID, targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT name FROM upstreams WHERE org_id = $1 AND name = ANY($2) FOR SHARE`, org, targets)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range targets {
		if !found[t] {
			return &unknownTargetError{name: t}
		}
	}
	return nil
}

// routeTargets lists the distinct targets of a rule list.
func routeTargets(rules []policy.Rule) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rules {
		if r.Action == policy.ActionRoute && !seen[r.RouteTarget] {
			seen[r.RouteTarget] = true
			out = append(out, r.RouteTarget)
		}
	}
	return out
}
