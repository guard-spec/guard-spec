package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Rule editing helpers for the admin UI: the schema of rule conditions, and
// conversion between the stored condition tree and its text form. None of
// them touches an organization.

func policySchema() fiber.Handler {
	schema := policy.RuleSchema()
	return func(c *fiber.Ctx) error { return c.JSON(schema) }
}

// parseCondition returns the condition tree for a text, or 422 with the
// offset (in characters) of the problem.
func parseCondition(eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Text *string `json:"text"`
		}
		if err := json.Unmarshal(c.Body(), &req); err != nil || req.Text == nil {
			return c.Status(400).JSON(fiber.Map{"error": "text is required"})
		}
		tree, err := parseAndValidate(eng, *req.Text)
		if err != nil {
			pe, _ := policy.AsParseError(err)
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": pe.Message, "position": pe.Position})
		}
		return c.JSON(fiber.Map{"condition": tree})
	}
}

// parseAndValidate parses text and validates the resulting CEL as a stored
// rule would be. Every error is a *policy.ParseError.
func parseAndValidate(eng *policy.Engine, text string) (json.RawMessage, error) {
	tree, err := policy.ParseCondition(text)
	if err != nil {
		return nil, err
	}
	expr, err := policy.JSONASTToCEL(tree)
	if err == nil {
		err = eng.ValidateCEL(expr)
	}
	if err != nil {
		return nil, &policy.ParseError{Message: err.Error()}
	}
	return tree, nil
}

// formatCondition renders a condition tree as text, or 422 for an invalid tree.
func formatCondition() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Condition json.RawMessage `json:"condition"`
		}
		if err := json.Unmarshal(c.Body(), &req); err != nil || len(req.Condition) == 0 {
			return c.Status(400).JSON(fiber.Map{"error": "condition is required"})
		}
		text, err := policy.FormatCondition(req.Condition)
		if err != nil {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"text": text})
	}
}

// ── Simulator ─────────────────────────────────────────────────────────────────

type simUpstream struct {
	Source  string `json:"source"` // rule, project, org, env or stub
	Name    string `json:"name"`
	BaseURL string `json:"base_url"`
	// Error is set when the gateway would fail the request closed (502)
	// because the upstream is missing or disabled.
	Error string `json:"error,omitempty"`
}

type simDecision struct {
	Action      string      `json:"action"` // allow, block, route; error when the gateway would answer 503
	RuleID      *uuid.UUID  `json:"rule_id"`
	RuleName    string      `json:"rule_name"`
	RouteTarget string      `json:"route_target"`
	Logged      []uuid.UUID `json:"logged"`
	// LogOnly: what log-only policies would have decided (recorded, not applied).
	LogOnly []policy.LogOnlyMatch `json:"log_only"`
	Error   string                `json:"error,omitempty"`
}

// simulatePolicies runs policies against the given field values and reports
// each rule, the decision and the upstream the gateway would pick. Nothing is
// stored and nothing is sent upstream.
func simulatePolicies(db *pgxpool.Pool, eng *policy.Engine, settings *appSettings) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			PolicyID  *uuid.UUID      `json:"policy_id"`
			Rules     json.RawMessage `json:"rules"`
			ProjectID *uuid.UUID      `json:"project_id"`
			Vars      map[string]any  `json:"vars"`
		}
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body: " + err.Error()})
		}
		vars, err := policy.VarsFromMap(req.Vars)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "vars: " + err.Error()})
		}
		if vars.RequestTenantID == "" {
			vars.RequestTenantID = org.String()
		}
		var unsaved []policy.Rule
		if len(req.Rules) > 0 && string(req.Rules) != "null" {
			if unsaved, err = eng.ValidateRules(req.Rules); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "rules: " + err.Error()})
			}
		}

		ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
		defer cancel()
		var (
			trace    []policy.TraceEntry
			decision policy.Decision
			failed   error
			up       *simUpstream
		)
		err = tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
			if err := checkProject(ctx, tx, org, req.ProjectID); err != nil {
				return err
			}
			var policies []policy.SimPolicy
			switch {
			case unsaved != nil:
				policies = []policy.SimPolicy{{ID: req.PolicyID, Rules: unsaved}}
			default:
				var err error
				if policies, err = loadSimPolicies(ctx, tx, org, req.PolicyID, req.ProjectID); err != nil {
					return err
				}
			}
			trace, decision, failed = eng.Simulate(ctx, policies, vars)
			if failed != nil || decision.Action == policy.ActionBlock {
				return nil
			}
			var err error
			up, err = simulateRoute(ctx, tx, org, req.ProjectID, decision, settings.envUpstreamURL)
			return err
		})
		switch {
		case errors.Is(err, errUnknownProject):
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		case errors.Is(err, errPolicyNotFound):
			return c.Status(404).JSON(fiber.Map{"error": "policy not found"})
		case err != nil:
			return serverError(c, err)
		}
		out := simDecision{Action: string(decision.Action), RuleName: decision.RuleName,
			RouteTarget: decision.RouteTarget, Logged: decision.Logged, LogOnly: decision.LogOnly}
		if decision.RuleID != uuid.Nil {
			out.RuleID = &decision.RuleID
		}
		if out.Logged == nil {
			out.Logged = []uuid.UUID{}
		}
		if out.LogOnly == nil {
			out.LogOnly = []policy.LogOnlyMatch{}
		}
		if failed != nil {
			out = simDecision{Action: "error", Logged: []uuid.UUID{}, LogOnly: []policy.LogOnlyMatch{}, Error: failed.Error()}
		}
		return c.JSON(fiber.Map{"trace": trace, "decision": out, "upstream": up})
	}
}

var errPolicyNotFound = errors.New("policy not found")

// loadSimPolicies loads one policy (enabled or not), or the enabled policies
// the gateway would run for a key of project, in its order (dbPolicyLoader).
func loadSimPolicies(ctx context.Context, tx pgx.Tx, org uuid.UUID, policyID, project *uuid.UUID) ([]policy.SimPolicy, error) {
	query := `SELECT id, rules, log_only FROM policies
	          WHERE org_id = $1 AND enabled AND (project_id IS NULL OR project_id = $2)
	          ORDER BY project_id IS NULL, created_at, id`
	args := []any{org, project}
	if policyID != nil {
		query = `SELECT id, rules, log_only FROM policies WHERE org_id = $1 AND id = $2`
		args = []any{org, *policyID}
	}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []policy.SimPolicy
	for rows.Next() {
		var id uuid.UUID
		var raw []byte
		var logOnly bool
		if err := rows.Scan(&id, &raw, &logOnly); err != nil {
			return nil, err
		}
		p := policy.SimPolicy{ID: &id, LogOnly: logOnly}
		if err := json.Unmarshal(raw, &p.Rules); err != nil {
			return nil, fmt.Errorf("policy %s: %w", id, err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if policyID != nil && len(out) == 0 {
		return nil, errPolicyNotFound
	}
	return out, nil
}

// simulateRoute resolves the upstream as the gateway does (cmd/gateway,
// routing.go). The env step uses the control plane's UPSTREAM_LLM_URL, which
// should be the gateway's.
func simulateRoute(ctx context.Context, tx pgx.Tx, org uuid.UUID, project *uuid.UUID, d policy.Decision, envURL string) (*simUpstream, error) {
	describe := func(u *upstream, source string) *simUpstream {
		s := &simUpstream{Source: source, Name: u.Name, BaseURL: u.BaseURL}
		if !u.Enabled {
			s.Error = "upstream is disabled; the gateway answers 502"
		}
		return s
	}
	if d.Action == policy.ActionRoute {
		u, err := scanUpstreamRow(tx.QueryRow(ctx, upstreamSelect+` WHERE org_id = $1 AND name = $2`, org, d.RouteTarget))
		if errors.Is(err, pgx.ErrNoRows) {
			return &simUpstream{Source: "rule", Name: d.RouteTarget,
				Error: "no such upstream; the gateway answers 502"}, nil
		}
		if err != nil {
			return nil, err
		}
		return describe(&u, "rule"), nil
	}
	if project != nil {
		u, err := scanUpstreamRow(tx.QueryRow(ctx, upstreamSelect+
			` WHERE id = (SELECT default_upstream_id FROM projects WHERE id = $1 AND org_id = $2) AND org_id = $2`, *project, org))
		if err == nil {
			return describe(&u, "project"), nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	u, err := scanUpstreamRow(tx.QueryRow(ctx, upstreamSelect+
		` WHERE id = (SELECT default_upstream_id FROM organizations WHERE id = $1) AND org_id = $1`, org))
	if err == nil {
		return describe(&u, "org"), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if envURL != "" {
		return &simUpstream{Source: "env", BaseURL: envURL}, nil
	}
	return &simUpstream{Source: "stub"}, nil
}
