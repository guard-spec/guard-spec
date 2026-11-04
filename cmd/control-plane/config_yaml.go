package main

// Config as code: GET /organizations/:orgId/config returns the org's upstreams,
// defaults and policies as YAML; PUT applies such a file in one transaction.
// The file is the whole truth: upstreams and policies it does not list are
// deleted, and defaults it does not set are cleared. Projects themselves are
// not created or deleted here, only their default upstream.
//
// Identity is by name: an upstream by its name, a policy by its name, and a
// rule by its name inside its policy, so that a rule keeps its ID (and audit
// rows keep naming it) across applies. The order of policies in the file is
// their evaluation order within each scope (project policies, then org-wide).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/policy"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

const (
	configVersion      = 1
	maxConfigBytes     = 1 << 20
	maxConfigPolicies  = 500
	maxConfigUpstreams = 200
	maxPolicyNameLen   = 200
)

type configDoc struct {
	Version         int               `yaml:"version"`
	DefaultUpstream *string           `yaml:"default_upstream"`
	ProjectDefaults map[string]string `yaml:"project_defaults,omitempty"` // project slug -> upstream name
	Upstreams       []configUpstream  `yaml:"upstreams"`
	Policies        []configPolicy    `yaml:"policies"`
}

type configUpstream struct {
	Name      string `yaml:"name"`
	BaseURL   string `yaml:"base_url"`
	Model     string `yaml:"model,omitempty"`
	APIKeyEnv string `yaml:"api_key_env,omitempty"`
	TimeoutMs int    `yaml:"timeout_ms,omitempty"`
	Enabled   *bool  `yaml:"enabled,omitempty"`
}

type configPolicy struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description,omitempty"`
	Project     *string      `yaml:"project"` // project slug; null: org-wide
	Enabled     *bool        `yaml:"enabled"`
	Rules       []configRule `yaml:"rules"`
}

type configRule struct {
	Name        string `yaml:"name"`
	When        string `yaml:"when"`
	Action      string `yaml:"action"`
	RouteTarget string `yaml:"route_target,omitempty"`
}

// configChange is one difference between the stored config and the file.
type configChange struct {
	Kind string `json:"kind"` // upstream, policy or default
	Name string `json:"name"` // default: "org" or "project:<slug>"
	Op   string `json:"op"`   // create, update or delete
}

type configError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ── Stored state ──────────────────────────────────────────────────────────────

type storedProject struct {
	ID              uuid.UUID
	Slug            string
	DefaultUpstream *uuid.UUID
}

type configPolicyRow struct {
	ID          uuid.UUID
	Name        string
	Description string
	ProjectID   *uuid.UUID
	Enabled     bool
	Rules       []policy.Rule
	CreatedAt   time.Time
}

type storedConfig struct {
	upstreams  []upstream
	orgDefault *uuid.UUID
	projects   []storedProject
	policies   []configPolicyRow // in created_at order
}

func loadStoredConfig(ctx context.Context, tx pgx.Tx, org uuid.UUID, lock bool) (*storedConfig, error) {
	s := &storedConfig{}
	q := `SELECT default_upstream_id FROM organizations WHERE id = $1`
	if lock {
		// Serializes applies of the same org.
		q += ` FOR UPDATE`
	}
	if err := tx.QueryRow(ctx, q, org).Scan(&s.orgDefault); err != nil {
		return nil, err
	}
	var err error
	if s.upstreams, err = loadUpstreams(ctx, tx, org); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT id, slug, default_upstream_id FROM projects WHERE org_id = $1 ORDER BY slug`, org)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p storedProject
		if err := rows.Scan(&p.ID, &p.Slug, &p.DefaultUpstream); err != nil {
			rows.Close()
			return nil, err
		}
		s.projects = append(s.projects, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT id, name, COALESCE(description, ''), project_id, enabled, rules, created_at
		FROM policies WHERE org_id = $1 ORDER BY created_at, id`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p configPolicyRow
		var raw []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.ProjectID, &p.Enabled, &raw, &p.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &p.Rules); err != nil {
			return nil, fmt.Errorf("policy %s: %w", p.ID, err)
		}
		s.policies = append(s.policies, p)
	}
	return s, rows.Err()
}

func (s *storedConfig) upstreamName(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	for _, u := range s.upstreams {
		if u.ID == *id {
			name := u.Name
			return &name
		}
	}
	return nil
}

func (s *storedConfig) projectSlug(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	for _, p := range s.projects {
		if p.ID == *id {
			slug := p.Slug
			return &slug
		}
	}
	return nil
}

// ── GET ───────────────────────────────────────────────────────────────────────

func getConfig(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var stored *storedConfig
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			stored, err = loadStoredConfig(c.Context(), tx, org, false)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		doc, err := stored.document()
		if err != nil {
			slog.Error("config export failed", "org", org, "err", err)
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(doc); err != nil {
			return serverError(c, err)
		}
		c.Set(fiber.HeaderContentType, "text/yaml; charset=utf-8")
		return c.Send(buf.Bytes())
	}
}

// document renders the stored config as a file.
func (s *storedConfig) document() (*configDoc, error) {
	doc := &configDoc{Version: configVersion, DefaultUpstream: s.upstreamName(s.orgDefault),
		Upstreams: []configUpstream{}, Policies: []configPolicy{}}
	for _, u := range s.upstreams {
		cu := configUpstream{Name: u.Name, BaseURL: u.BaseURL, Model: u.Model, APIKeyEnv: u.APIKeyEnv}
		if u.TimeoutMs != defaultTimeoutMs {
			cu.TimeoutMs = u.TimeoutMs
		}
		if !u.Enabled {
			cu.Enabled = &u.Enabled
		}
		doc.Upstreams = append(doc.Upstreams, cu)
	}
	for _, p := range s.projects {
		if name := s.upstreamName(p.DefaultUpstream); name != nil {
			if doc.ProjectDefaults == nil {
				doc.ProjectDefaults = map[string]string{}
			}
			doc.ProjectDefaults[p.Slug] = *name
		}
	}
	for _, p := range s.policies {
		enabled := p.Enabled
		cp := configPolicy{Name: p.Name, Description: p.Description, Project: s.projectSlug(p.ProjectID),
			Enabled: &enabled, Rules: []configRule{}}
		for _, r := range p.Rules {
			when, err := policy.FormatStoredCondition(r.Condition)
			if err != nil {
				return nil, fmt.Errorf("policy %q rule %q cannot be written as text: %w", p.Name, r.Name, err)
			}
			cp.Rules = append(cp.Rules, configRule{Name: r.Name, When: when, Action: string(r.Action),
				RouteTarget: r.RouteTarget})
		}
		doc.Policies = append(doc.Policies, cp)
	}
	return doc, nil
}

// ── PUT ───────────────────────────────────────────────────────────────────────

// errDryRun rolls back a dry run's transaction.
var errDryRun = errors.New("dry run")

// configInvalid carries validation errors out of the transaction.
type configInvalid struct{ errs []configError }

func (e *configInvalid) Error() string { return "invalid config" }

func putConfig(db *pgxpool.Pool, eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		dryRun := c.QueryBool("dry_run", false)
		body := c.Body()
		if len(body) > maxConfigBytes {
			return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "config is larger than 1 MiB"})
		}
		doc, errs := decodeConfig(body)
		if len(errs) > 0 {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"errors": errs})
		}
		// Conditions and fields that need no database are checked first.
		plan, errs := validateConfig(eng, doc)
		if len(errs) > 0 {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"errors": errs})
		}
		var changes []configChange
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			stored, err := loadStoredConfig(c.Context(), tx, org, true)
			if err != nil {
				return err
			}
			if errs := plan.resolveProjects(stored); len(errs) > 0 {
				return &configInvalid{errs: errs}
			}
			changes = plan.diff(stored)
			if dryRun {
				return errDryRun
			}
			return plan.apply(c.Context(), tx, org, stored)
		})
		var invalid *configInvalid
		switch {
		case errors.As(err, &invalid):
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"errors": invalid.errs})
		case errors.Is(err, errDryRun):
		case err != nil:
			return serverError(c, err)
		}
		if !dryRun && len(changes) > 0 {
			slog.Info("config applied", "org", org, "changes", len(changes), "by", auth.UserID(c))
		}
		return c.JSON(fiber.Map{"applied": !dryRun, "changes": changes})
	}
}

// decodeConfig reads one YAML document with known fields only.
func decodeConfig(body []byte) (*configDoc, []configError) {
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	var doc configDoc
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, []configError{{Path: "", Message: "config is empty"}}
		}
		return nil, []configError{{Path: "", Message: "yaml: " + strings.TrimPrefix(err.Error(), "yaml: ")}}
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, []configError{{Path: "", Message: "config must be a single YAML document"}}
	}
	return &doc, nil
}

// configPlan is a validated file, ready to compare and apply.
type configPlan struct {
	doc       *configDoc
	upstreams []upstream            // validated, in file order
	rules     [][]policy.Rule       // per policy: parsed rules without IDs
	texts     [][]string            // per policy: canonical text of each condition
	projects  map[string]*uuid.UUID // slug -> id, filled by resolveProjects
}

func validateConfig(eng *policy.Engine, doc *configDoc) (*configPlan, []configError) {
	var errs []configError
	add := func(path, format string, args ...any) {
		errs = append(errs, configError{Path: path, Message: fmt.Sprintf(format, args...)})
	}
	if doc.Version != configVersion {
		add("version", "version must be %d", configVersion)
	}
	if len(doc.Upstreams) > maxConfigUpstreams {
		add("upstreams", "at most %d upstreams", maxConfigUpstreams)
	}
	if len(doc.Policies) > maxConfigPolicies {
		add("policies", "at most %d policies", maxConfigPolicies)
	}
	plan := &configPlan{doc: doc}
	names := map[string]bool{}
	for i, cu := range doc.Upstreams {
		path := fmt.Sprintf("upstreams[%d]", i)
		u := upstream{Name: cu.Name, BaseURL: cu.BaseURL, Model: cu.Model, APIKeyEnv: cu.APIKeyEnv,
			TimeoutMs: cu.TimeoutMs, Enabled: cu.Enabled == nil || *cu.Enabled}
		if err := u.validate(); err != nil {
			add(path, "%s", err.Error())
		}
		if names[u.Name] {
			add(path+".name", "upstream %q is listed twice", u.Name)
		}
		names[u.Name] = true
		plan.upstreams = append(plan.upstreams, u)
	}
	if doc.DefaultUpstream != nil && !names[*doc.DefaultUpstream] {
		add("default_upstream", "%q is not an upstream of this file", *doc.DefaultUpstream)
	}
	for slug, name := range doc.ProjectDefaults {
		if !names[name] {
			add("project_defaults."+slug, "%q is not an upstream of this file", name)
		}
	}
	policyNames := map[string]bool{}
	for i, cp := range doc.Policies {
		path := fmt.Sprintf("policies[%d]", i)
		if cp.Name == "" || len(cp.Name) > maxPolicyNameLen {
			add(path+".name", "name is required (at most %d characters)", maxPolicyNameLen)
		}
		if policyNames[cp.Name] {
			add(path+".name", "policy %q is listed twice", cp.Name)
		}
		policyNames[cp.Name] = true
		if len(cp.Rules) > policy.MaxRules {
			add(path+".rules", "a policy may hold at most %d rules", policy.MaxRules)
		}
		var rules []policy.Rule
		var texts []string
		for j, cr := range cp.Rules {
			rpath := fmt.Sprintf("%s.rules[%d]", path, j)
			rule := policy.Rule{Name: cr.Name, Action: policy.Action(cr.Action), RouteTarget: cr.RouteTarget}
			tree, err := parseAndValidate(eng, cr.When)
			if err != nil {
				pe, _ := policy.AsParseError(err)
				add(rpath+".when", "%s (at position %d)", pe.Message, pe.Position)
				rules, texts = append(rules, rule), append(texts, "")
				continue
			}
			rule.Condition = tree
			text, _ := policy.FormatCondition(tree)
			if err := eng.ValidateRule(&rule); err != nil {
				add(rpath, "%s", err.Error())
			} else if rule.Action == policy.ActionRoute && !names[rule.RouteTarget] {
				add(rpath+".route_target", "%q is not an upstream of this file", rule.RouteTarget)
			}
			rules, texts = append(rules, rule), append(texts, text)
		}
		plan.rules = append(plan.rules, rules)
		plan.texts = append(plan.texts, texts)
	}
	return plan, errs
}

// resolveProjects maps the project slugs of the file to the org's projects.
func (p *configPlan) resolveProjects(s *storedConfig) []configError {
	var errs []configError
	p.projects = map[string]*uuid.UUID{}
	bySlug := map[string]uuid.UUID{}
	for _, pr := range s.projects {
		bySlug[pr.Slug] = pr.ID
	}
	resolve := func(path, slug string) {
		id, ok := bySlug[slug]
		if !ok {
			errs = append(errs, configError{Path: path, Message: fmt.Sprintf("no project with slug %q", slug)})
			return
		}
		p.projects[slug] = &id
	}
	for i, cp := range p.doc.Policies {
		if cp.Project != nil {
			resolve(fmt.Sprintf("policies[%d].project", i), *cp.Project)
		}
	}
	slugs := make([]string, 0, len(p.doc.ProjectDefaults))
	for slug := range p.doc.ProjectDefaults {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		resolve("project_defaults."+slug, slug)
	}
	return errs
}

func (p *configPlan) projectOf(i int) *uuid.UUID {
	if slug := p.doc.Policies[i].Project; slug != nil {
		return p.projects[*slug]
	}
	return nil
}

// policyMatch pairs each policy of the file with the stored policy of the
// same name (the oldest, when names repeat). Stored policies left over are
// deleted.
func (p *configPlan) policyMatch(s *storedConfig) (matched []*configPolicyRow, removed []*configPolicyRow) {
	used := make([]bool, len(s.policies))
	for _, cp := range p.doc.Policies {
		var m *configPolicyRow
		for k := range s.policies {
			if !used[k] && s.policies[k].Name == cp.Name {
				used[k], m = true, &s.policies[k]
				break
			}
		}
		matched = append(matched, m)
	}
	for k := range s.policies {
		if !used[k] {
			removed = append(removed, &s.policies[k])
		}
	}
	return matched, removed
}

// rulesFor builds policy i's rules to store. A rule keeps the ID of the
// stored rule with the same name (in order, when names repeat), and keeps its
// stored condition when the text is the same, so that an apply without
// changes rewrites nothing.
func (p *configPlan) rulesFor(i int, stored *configPolicyRow) []policy.Rule {
	out := make([]policy.Rule, len(p.rules[i]))
	used := map[int]bool{}
	for j, r := range p.rules[i] {
		r.ID = uuid.Nil
		if stored != nil {
			for k, old := range stored.Rules {
				if used[k] || old.Name != r.Name {
					continue
				}
				used[k] = true
				r.ID = old.ID
				if text, err := policy.FormatStoredCondition(old.Condition); err == nil && text == p.texts[i][j] {
					r.Condition = old.Condition
				}
				break
			}
		}
		if r.ID == uuid.Nil {
			r.ID = uuid.New()
		}
		out[j] = r
	}
	return out
}

func sameRules(a, b []policy.Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Name != b[i].Name || a[i].Action != b[i].Action ||
			a[i].RouteTarget != b[i].RouteTarget || !bytes.Equal(a[i].Condition, b[i].Condition) {
			return false
		}
	}
	return true
}

func sameUUID(a, b *uuid.UUID) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// policyOrder returns the created_at each policy of the file needs so that
// the file order is the evaluation order: a stored time is kept while it is
// later than the previous policy's, otherwise it is moved just after it.
func (p *configPlan) policyOrder(matched []*configPolicyRow, now time.Time) []time.Time {
	out := make([]time.Time, len(matched))
	now = now.Truncate(time.Microsecond) // what PostgreSQL keeps
	var prev time.Time
	for i, m := range matched {
		t := now
		if m != nil {
			t = m.CreatedAt
		}
		if !prev.IsZero() && !t.After(prev) {
			t = prev.Add(time.Microsecond)
		}
		out[i], prev = t, t
	}
	return out
}

// diff lists what apply would change.
func (p *configPlan) diff(s *storedConfig) []configChange {
	changes := []configChange{}
	stored := map[string]upstream{}
	for _, u := range s.upstreams {
		stored[u.Name] = u
	}
	inFile := map[string]bool{}
	for _, u := range p.upstreams {
		inFile[u.Name] = true
		old, ok := stored[u.Name]
		switch {
		case !ok:
			changes = append(changes, configChange{"upstream", u.Name, "create"})
		case old.BaseURL != u.BaseURL || old.Model != u.Model || old.APIKeyEnv != u.APIKeyEnv ||
			old.TimeoutMs != u.TimeoutMs || old.Enabled != u.Enabled:
			changes = append(changes, configChange{"upstream", u.Name, "update"})
		}
	}
	for _, u := range s.upstreams {
		if !inFile[u.Name] {
			changes = append(changes, configChange{"upstream", u.Name, "delete"})
		}
	}

	defaultChange := func(name string, old, want *string) {
		switch {
		case old == nil && want != nil:
			changes = append(changes, configChange{"default", name, "create"})
		case old != nil && want == nil:
			changes = append(changes, configChange{"default", name, "delete"})
		case old != nil && *old != *want:
			changes = append(changes, configChange{"default", name, "update"})
		}
	}
	defaultChange("org", s.upstreamName(s.orgDefault), p.doc.DefaultUpstream)
	for _, pr := range s.projects {
		var want *string
		if name, ok := p.doc.ProjectDefaults[pr.Slug]; ok {
			want = &name
		}
		defaultChange("project:"+pr.Slug, s.upstreamName(pr.DefaultUpstream), want)
	}

	matched, removed := p.policyMatch(s)
	order := p.policyOrder(matched, time.Now())
	for i, cp := range p.doc.Policies {
		m := matched[i]
		if m == nil {
			changes = append(changes, configChange{"policy", cp.Name, "create"})
			continue
		}
		enabled := cp.Enabled == nil || *cp.Enabled
		if m.Description != cp.Description || m.Enabled != enabled || !sameUUID(m.ProjectID, p.projectOf(i)) ||
			!sameRules(m.Rules, p.rulesFor(i, m)) || !order[i].Equal(m.CreatedAt) {
			changes = append(changes, configChange{"policy", cp.Name, "update"})
		}
	}
	for _, r := range removed {
		changes = append(changes, configChange{"policy", r.Name, "delete"})
	}
	return changes
}

// apply writes the file. The order keeps every reference valid at each step:
// upstreams are created first and deleted last, after the defaults and rules
// that named them have changed.
func (p *configPlan) apply(ctx context.Context, tx pgx.Tx, org uuid.UUID, s *storedConfig) error {
	stored := map[string]upstream{}
	for _, u := range s.upstreams {
		stored[u.Name] = u
	}
	ids := map[string]uuid.UUID{}
	for _, u := range p.upstreams {
		old, ok := stored[u.Name]
		if !ok {
			var id uuid.UUID
			if err := tx.QueryRow(ctx,
				`INSERT INTO upstreams (org_id, name, base_url, model, api_key_env, timeout_ms, enabled)
				 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
				org, u.Name, u.BaseURL, u.Model, nullString(u.APIKeyEnv), u.TimeoutMs, u.Enabled).Scan(&id); err != nil {
				return fmt.Errorf("upstream %s: %w", u.Name, err)
			}
			ids[u.Name] = id
			continue
		}
		ids[u.Name] = old.ID
		if old.BaseURL != u.BaseURL || old.Model != u.Model || old.APIKeyEnv != u.APIKeyEnv ||
			old.TimeoutMs != u.TimeoutMs || old.Enabled != u.Enabled {
			if _, err := tx.Exec(ctx,
				`UPDATE upstreams SET base_url = $3, model = $4, api_key_env = $5, timeout_ms = $6, enabled = $7,
				   updated_at = NOW() WHERE id = $1 AND org_id = $2`,
				old.ID, org, u.BaseURL, u.Model, nullString(u.APIKeyEnv), u.TimeoutMs, u.Enabled); err != nil {
				return fmt.Errorf("upstream %s: %w", u.Name, err)
			}
		}
	}
	idOf := func(name *string) *uuid.UUID {
		if name == nil {
			return nil
		}
		id := ids[*name]
		return &id
	}

	if want := idOf(p.doc.DefaultUpstream); !sameUUID(want, s.orgDefault) {
		if _, err := tx.Exec(ctx, `UPDATE organizations SET default_upstream_id = $1, updated_at = NOW() WHERE id = $2`,
			want, org); err != nil {
			return err
		}
	}
	for _, pr := range s.projects {
		var want *uuid.UUID
		if name, ok := p.doc.ProjectDefaults[pr.Slug]; ok {
			want = idOf(&name)
		}
		if !sameUUID(want, pr.DefaultUpstream) {
			if _, err := tx.Exec(ctx, `UPDATE projects SET default_upstream_id = $1 WHERE id = $2 AND org_id = $3`,
				want, pr.ID, org); err != nil {
				return err
			}
		}
	}

	matched, removed := p.policyMatch(s)
	for _, r := range removed {
		if _, err := tx.Exec(ctx, `DELETE FROM policies WHERE id = $1 AND org_id = $2`, r.ID, org); err != nil {
			return err
		}
	}
	order := p.policyOrder(matched, time.Now())
	for i, cp := range p.doc.Policies {
		m := matched[i]
		rules := p.rulesFor(i, m)
		raw, err := json.Marshal(rules)
		if err != nil {
			return err
		}
		enabled := cp.Enabled == nil || *cp.Enabled
		project := p.projectOf(i)
		if m == nil {
			if _, err := tx.Exec(ctx,
				`INSERT INTO policies (org_id, project_id, name, description, enabled, rules, created_at, updated_at)
				 VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, NOW())`,
				org, project, cp.Name, cp.Description, enabled, raw, order[i]); err != nil {
				return fmt.Errorf("policy %s: %w", cp.Name, err)
			}
			continue
		}
		if m.Description == cp.Description && m.Enabled == enabled && sameUUID(m.ProjectID, project) &&
			sameRules(m.Rules, rules) && order[i].Equal(m.CreatedAt) {
			continue
		}
		if _, err := tx.Exec(ctx,
			`UPDATE policies SET description = NULLIF($3, ''), enabled = $4, project_id = $5, rules = $6,
			   created_at = $7, version = version + 1, updated_at = NOW()
			 WHERE id = $1 AND org_id = $2`,
			m.ID, org, cp.Description, enabled, project, raw, order[i]); err != nil {
			return fmt.Errorf("policy %s: %w", cp.Name, err)
		}
	}

	for _, u := range s.upstreams {
		if _, keep := ids[u.Name]; keep {
			continue
		}
		// Lock first, then look for users: a policy saved concurrently through
		// the API holds a share lock on the upstream it names until it commits.
		if _, err := lockUpstream(ctx, tx, org, u.ID); err != nil {
			return fmt.Errorf("upstream %s: %w", u.Name, err)
		}
		refs, err := upstreamRefs(ctx, tx, org, u.ID, u.Name)
		if err != nil {
			return err
		}
		if len(refs) > 0 {
			names := make([]string, len(refs))
			for i, r := range refs {
				names[i] = r.String()
			}
			return &configInvalid{errs: []configError{{Path: "upstreams",
				Message: fmt.Sprintf("upstream %q is not in the file but is still used by %s", u.Name, strings.Join(names, ", "))}}}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM upstreams WHERE id = $1 AND org_id = $2`, u.ID, org); err != nil {
			return fmt.Errorf("upstream %s: %w", u.Name, err)
		}
	}
	return nil
}
