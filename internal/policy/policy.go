package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
)

// Action is the guardrail decision for a matched rule.
type Action string

const (
	ActionAllow  Action = "allow"
	ActionBlock  Action = "block"
	ActionRedact Action = "redact"
	ActionRoute  Action = "route"
	ActionLog    Action = "log"
)

// Policy is the tenant-scoped ruleset. Stored as JSON in Postgres.
type Policy struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	ProjectID uuid.UUID `json:"project_id"`
	Version   int       `json:"version"`
	Rules     []Rule    `json:"rules"` // ordered; first match wins
}

// Rule is a single condition + action pair.
type Rule struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Condition   json.RawMessage `json:"condition"` // react-querybuilder JSON AST
	Action      Action          `json:"action"`
	RouteTarget string          `json:"route_target,omitempty"`
}

// Decision is the result of policy evaluation.
type Decision struct {
	Action      Action
	RuleID      uuid.UUID
	RuleName    string
	RouteTarget string
}

// DefaultAllow is returned when no rule matches.
var DefaultAllow = Decision{Action: ActionAllow}

// Vars holds the values available to CEL expressions for one request.
// Expensive signals (injection.score) are populated lazily via the Load* methods.
type Vars struct {
	RequestModel    string
	RequestTenantID string
	RequestTokens   int
	IsMCPResponse   bool

	AnomalyHasTagChars bool
	AnomalyHasBidi     bool
	AnomalyScore       float32

	// Set these before calling Evaluate when the rule may reference them.
	InjectionScore float64
	ToxicityScore  float64
	PIIEntities    []string
	TopicCategories []string
}

// toActivation converts Vars to the map cel.Program.ContextEval expects.
func (v *Vars) toActivation() map[string]any {
	return map[string]any{
		"request.model":         v.RequestModel,
		"request.tenant_id":     v.RequestTenantID,
		"request.tokens":        int64(v.RequestTokens),
		"injection.score":       v.InjectionScore,
		"pii.entities":          v.PIIEntities,
		"toxicity.score":        v.ToxicityScore,
		"topic.categories":      v.TopicCategories,
		"anomaly.has_tag_chars": v.AnomalyHasTagChars,
		"anomaly.has_bidi":      v.AnomalyHasBidi,
		"mcp.is_tool_response":  v.IsMCPResponse,
	}
}

// Engine compiles and caches CEL programs per (policy_id, version).
type Engine struct {
	env   *cel.Env
	mu    sync.RWMutex
	cache map[cacheKey]*compiledPolicy
}

type cacheKey struct {
	id      uuid.UUID
	version int
}

type compiledPolicy struct {
	rules []compiledRule
}

type compiledRule struct {
	id      uuid.UUID
	name    string
	action  Action
	target  string
	program cel.Program
}

// New creates an Engine with the standard CEL variable environment.
func New() (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("request.model", cel.StringType),
		cel.Variable("request.tenant_id", cel.StringType),
		cel.Variable("request.tokens", cel.IntType),
		cel.Variable("injection.score", cel.DoubleType),
		cel.Variable("pii.entities", cel.ListType(cel.StringType)),
		cel.Variable("toxicity.score", cel.DoubleType),
		cel.Variable("topic.categories", cel.ListType(cel.StringType)),
		cel.Variable("anomaly.has_tag_chars", cel.BoolType),
		cel.Variable("anomaly.has_bidi", cel.BoolType),
		cel.Variable("mcp.is_tool_response", cel.BoolType),
	)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	return &Engine{
		env:   env,
		cache: make(map[cacheKey]*compiledPolicy),
	}, nil
}

// Evaluate runs the policy against vars and returns the first matching decision.
func (e *Engine) Evaluate(ctx context.Context, p *Policy, v *Vars) (Decision, error) {
	compiled, err := e.getOrCompile(p)
	if err != nil {
		return DefaultAllow, err
	}

	activation := v.toActivation()
	for _, rule := range compiled.rules {
		out, _, err := rule.program.ContextEval(ctx, activation)
		if err != nil {
			continue // treat eval error as no-match
		}
		if matched, ok := out.Value().(bool); ok && matched {
			return Decision{
				Action:      rule.action,
				RuleID:      rule.id,
				RuleName:    rule.name,
				RouteTarget: rule.target,
			}, nil
		}
	}
	return DefaultAllow, nil
}

// ValidateCEL compiles a CEL expression and returns the compiled form or an error.
// Used by the control plane before persisting a rule.
func (e *Engine) ValidateCEL(expr string) error {
	ast, issues := e.env.Compile(expr)
	if issues.Err() != nil {
		return issues.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return fmt.Errorf("expression must return bool, got %s", ast.OutputType())
	}
	return nil
}

func (e *Engine) getOrCompile(p *Policy) (*compiledPolicy, error) {
	key := cacheKey{id: p.ID, version: p.Version}

	e.mu.RLock()
	if cp, ok := e.cache[key]; ok {
		e.mu.RUnlock()
		return cp, nil
	}
	e.mu.RUnlock()

	cp, err := e.compile(p)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	e.cache[key] = cp
	e.mu.Unlock()
	return cp, nil
}

func (e *Engine) compile(p *Policy) (*compiledPolicy, error) {
	cp := &compiledPolicy{}
	for _, rule := range p.Rules {
		celExpr, err := JSONASTToCEL(rule.Condition)
		if err != nil {
			return nil, fmt.Errorf("rule %s: ast->cel: %w", rule.ID, err)
		}

		ast, issues := e.env.Compile(celExpr)
		if issues.Err() != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, issues.Err())
		}

		prg, err := e.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return nil, fmt.Errorf("rule %s: program: %w", rule.ID, err)
		}

		cp.rules = append(cp.rules, compiledRule{
			id:      rule.ID,
			name:    rule.Name,
			action:  rule.Action,
			target:  rule.RouteTarget,
			program: prg,
		})
	}
	return cp, nil
}

// queryBuilderNode is the react-querybuilder JSON wire format.
type queryBuilderNode struct {
	Combinator string             `json:"combinator"` // "and" | "or"
	Rules      []json.RawMessage  `json:"rules"`
	Field      string             `json:"field"`
	Operator   string             `json:"operator"`
	Value      any                `json:"value"`
}

// JSONASTToCEL converts the react-querybuilder JSON AST to a CEL expression string.
// Server-side only — never trust client-supplied CEL strings.
func JSONASTToCEL(raw json.RawMessage) (string, error) {
	var node queryBuilderNode
	if err := json.Unmarshal(raw, &node); err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}
	return nodeToCEL(node)
}

func nodeToCEL(node queryBuilderNode) (string, error) {
	// Group node (has combinator + rules)
	if node.Combinator != "" {
		parts := make([]string, 0, len(node.Rules))
		for _, raw := range node.Rules {
			var child queryBuilderNode
			if err := json.Unmarshal(raw, &child); err != nil {
				return "", err
			}
			expr, err := nodeToCEL(child)
			if err != nil {
				return "", err
			}
			parts = append(parts, "("+expr+")")
		}
		op := " && "
		if strings.EqualFold(node.Combinator, "or") {
			op = " || "
		}
		return strings.Join(parts, op), nil
	}

	// Leaf node (has field + operator + value)
	field := node.Field
	if field == "" {
		return "true", nil
	}

	switch node.Operator {
	case "=", "==":
		return fmt.Sprintf("%s == %s", field, celValue(node.Value)), nil
	case "!=":
		return fmt.Sprintf("%s != %s", field, celValue(node.Value)), nil
	case ">":
		return fmt.Sprintf("%s > %s", field, celValue(node.Value)), nil
	case ">=":
		return fmt.Sprintf("%s >= %s", field, celValue(node.Value)), nil
	case "<":
		return fmt.Sprintf("%s < %s", field, celValue(node.Value)), nil
	case "<=":
		return fmt.Sprintf("%s <= %s", field, celValue(node.Value)), nil
	case "contains":
		return fmt.Sprintf("%s.contains(%s)", field, celValue(node.Value)), nil
	case "in":
		return fmt.Sprintf("%s in %s", celValue(node.Value), field), nil
	default:
		return "", fmt.Errorf("unknown operator: %s", node.Operator)
	}
}

func celValue(v any) string {
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("%q", val)
	case float64:
		return fmt.Sprintf("%g", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", val)
	}
}
