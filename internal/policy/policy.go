package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
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
	Matched     bool
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

	InjectionLabel string

	AnomalyHasTagChars bool
	AnomalyHasBidi     bool
	AnomalyScore       float32

	// Set these before calling Evaluate when the rule may reference them.
	InjectionScore  float64
	ToxicityScore   float64
	PIIEntities     []string
	TopicCategories []string
}

// toActivation converts Vars to the map cel.Program.ContextEval expects.
func (v *Vars) toActivation() map[string]any {
	return map[string]any{
		"request.model":         v.RequestModel,
		"request.tenant_id":     v.RequestTenantID,
		"request.tokens":        int64(v.RequestTokens),
		"injection.score":       v.InjectionScore,
		"injection.label":       v.InjectionLabel,
		"pii.entities":          v.PIIEntities,
		"toxicity.score":        v.ToxicityScore,
		"topic.categories":      v.TopicCategories,
		"anomaly.score":         float64(v.AnomalyScore),
		"anomaly.has_tag_chars": v.AnomalyHasTagChars,
		"anomaly.has_bidi":      v.AnomalyHasBidi,
		"mcp.is_tool_response":  v.IsMCPResponse,
	}
}

// costLimit bounds one rule's evaluation. A rule the builder can express costs
// far less, so reaching it means something is wrong and the request fails closed.
const costLimit = 100_000

// totalCostBudget bounds all rules of one request together. One tenant can store
// many rules, each just under costLimit; without a shared budget a request could
// spend MaxRules*costLimit on the gateway's CPU. Reaching it fails closed.
const totalCostBudget = 1_000_000

// MaxRules is the most rules one policy may hold. The control plane refuses a
// larger list. It caps the per-request evaluation work a single policy can cause.
const MaxRules = 200

// interruptCheckFrequency is how many loop iterations pass between ctx checks.
const interruptCheckFrequency = 100

// ErrCostBudget means a request's rules together exceeded the evaluation budget.
var ErrCostBudget = errors.New("policy evaluation cost budget exceeded")

// listOfStrings is the type of the list fields.
var listOfStrings = cel.ListType(cel.StringType)

// fieldTypes lists the variables a rule can reference.
var fieldTypes = map[string]*cel.Type{
	"request.model":         cel.StringType,
	"request.tenant_id":     cel.StringType,
	"request.tokens":        cel.IntType,
	"injection.score":       cel.DoubleType,
	"injection.label":       cel.StringType,
	"pii.entities":          listOfStrings,
	"toxicity.score":        cel.DoubleType,
	"topic.categories":      listOfStrings,
	"anomaly.score":         cel.DoubleType,
	"anomaly.has_tag_chars": cel.BoolType,
	"anomaly.has_bidi":      cel.BoolType,
	"mcp.is_tool_response":  cel.BoolType,
}

// Engine compiles and caches CEL programs per policy id. Only the newest version
// of each policy is kept, so updates do not grow the cache.
type Engine struct {
	env        *cel.Env
	costLimit  uint64
	costBudget uint64
	mu         sync.RWMutex
	cache      map[uuid.UUID]*compiledPolicy
}

type compiledPolicy struct {
	version int
	rules   []compiledRule
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
	return NewWithCostLimit(costLimit)
}

// NewWithCostLimit is New with a different bound on one rule's evaluation.
func NewWithCostLimit(limit uint64) (*Engine, error) {
	opts := make([]cel.EnvOption, 0, len(fieldTypes))
	for name, typ := range fieldTypes {
		opts = append(opts, cel.Variable(name, typ))
	}
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	return &Engine{
		env:        env,
		costLimit:  limit,
		costBudget: totalCostBudget,
		cache:      make(map[uuid.UUID]*compiledPolicy),
	}, nil
}

// Evaluate runs the policy against vars and returns the first matching decision.
// On error the decision is empty: the caller must fail closed, not treat it as allow.
func (e *Engine) Evaluate(ctx context.Context, p *Policy, v *Vars) (Decision, error) {
	compiled, err := e.getOrCompile(p)
	if err != nil {
		return Decision{}, err
	}
	var spent uint64
	return compiled.evaluate(ctx, v, e.costBudget, &spent)
}

// EvaluateAll runs policies in order; the first match across them wins. Every
// policy is compiled first, so a broken one fails even when an earlier rule matches.
func (e *Engine) EvaluateAll(ctx context.Context, policies []Policy, v *Vars) (Decision, error) {
	compiled := make([]*compiledPolicy, 0, len(policies))
	for i := range policies {
		cp, err := e.getOrCompile(&policies[i])
		if err != nil {
			return Decision{}, fmt.Errorf("policy %s: %w", policies[i].ID, err)
		}
		compiled = append(compiled, cp)
	}
	var spent uint64
	for _, cp := range compiled {
		decision, err := cp.evaluate(ctx, v, e.costBudget, &spent)
		if err != nil || decision.Matched {
			return decision, err
		}
	}
	return DefaultAllow, nil
}

// evaluate runs the rules in order. spent carries the cost of every rule run so
// far for this request, across policies; budget bounds it. A cancelled or expired
// ctx stops evaluation between rules, as the interrupt check does within one.
func (cp *compiledPolicy) evaluate(ctx context.Context, v *Vars, budget uint64, spent *uint64) (Decision, error) {
	activation := v.toActivation()
	for _, rule := range cp.rules {
		if err := ctx.Err(); err != nil {
			return Decision{}, fmt.Errorf("rule %s: %w", rule.id, err)
		}
		out, details, err := rule.program.ContextEval(ctx, activation)
		if err != nil {
			return Decision{}, fmt.Errorf("rule %s: %w", rule.id, err)
		}
		if details == nil || details.ActualCost() == nil {
			return Decision{}, fmt.Errorf("rule %s: evaluation cost not tracked", rule.id)
		}
		*spent += *details.ActualCost()
		if *spent > budget {
			return Decision{}, fmt.Errorf("rule %s: %w", rule.id, ErrCostBudget)
		}
		matched, ok := out.Value().(bool)
		if !ok {
			return Decision{}, fmt.Errorf("rule %s: result is not a bool", rule.id)
		}
		if matched {
			return Decision{
				Matched:     true,
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
	_, err := e.compileExpr(expr)
	return err
}

// ValidateRules checks a rule list before it is saved and returns it with every
// rule carrying an ID, so that audit rows can name the rule that matched.
func (e *Engine) ValidateRules(raw json.RawMessage) ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, err
	}
	if rules == nil {
		return nil, errors.New("rules must be a list")
	}
	if len(rules) > MaxRules {
		return nil, fmt.Errorf("a policy may hold at most %d rules, got %d", MaxRules, len(rules))
	}
	seen := make(map[uuid.UUID]bool, len(rules))
	for i := range rules {
		rule := &rules[i]
		switch rule.Action {
		case ActionAllow, ActionBlock, ActionLog:
		case ActionRedact, ActionRoute:
			return nil, fmt.Errorf("rule %q: action %q is not implemented by the gateway", rule.Name, rule.Action)
		default:
			return nil, fmt.Errorf("rule %q: unknown action %q", rule.Name, rule.Action)
		}
		celExpr, err := JSONASTToCEL(rule.Condition)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		if err := e.ValidateCEL(celExpr); err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		if rule.ID == uuid.Nil {
			rule.ID = uuid.New()
		}
		if seen[rule.ID] {
			return nil, fmt.Errorf("rule %q: duplicate id %s", rule.Name, rule.ID)
		}
		seen[rule.ID] = true
	}
	return rules, nil
}

// getOrCompile keeps one entry per policy id: compiling a newer version replaces
// the older one. A request still holding an older version compiles it without
// caching it, so a late reader cannot push the newer version out.
func (e *Engine) getOrCompile(p *Policy) (*compiledPolicy, error) {
	e.mu.RLock()
	cached, ok := e.cache[p.ID]
	e.mu.RUnlock()
	if ok && cached.version == p.Version {
		return cached, nil
	}

	cp, err := e.compile(p)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	if cur, ok := e.cache[p.ID]; !ok || cur.version <= p.Version {
		e.cache[p.ID] = cp
	}
	e.mu.Unlock()
	return cp, nil
}

func (e *Engine) compile(p *Policy) (*compiledPolicy, error) {
	cp := &compiledPolicy{version: p.Version}
	for _, rule := range p.Rules {
		celExpr, err := JSONASTToCEL(rule.Condition)
		if err != nil {
			return nil, fmt.Errorf("rule %s: ast->cel: %w", rule.ID, err)
		}

		prg, err := e.compileExpr(celExpr)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
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

func (e *Engine) compileExpr(expr string) (cel.Program, error) {
	ast, issues := e.env.Compile(expr)
	if issues.Err() != nil {
		return nil, issues.Err()
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("expression must return bool, got %s", ast.OutputType())
	}
	prg, err := e.env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(e.costLimit),
		cel.InterruptCheckFrequency(interruptCheckFrequency))
	if err != nil {
		return nil, fmt.Errorf("program: %w", err)
	}
	return prg, nil
}

// queryBuilderNode is the react-querybuilder JSON wire format.
type queryBuilderNode struct {
	Combinator  string            `json:"combinator"` // "and" | "or"
	Not         bool              `json:"not"`
	Rules       []json.RawMessage `json:"rules"`
	Field       string            `json:"field"`
	Operator    string            `json:"operator"`
	Value       any               `json:"value"`
	ValueSource string            `json:"valueSource"`
	Disabled    bool              `json:"disabled"`
}

// JSONASTToCEL converts the react-querybuilder JSON AST to a CEL expression string.
// Server-side only — never trust client-supplied CEL strings. Fields come from
// fieldTypes and values are typed literals, so no client text is parsed as CEL.
func JSONASTToCEL(raw json.RawMessage) (string, error) {
	var node queryBuilderNode
	if err := json.Unmarshal(raw, &node); err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}
	return nodeToCEL(node)
}

func nodeToCEL(node queryBuilderNode) (string, error) {
	if node.Disabled {
		return "", errors.New("disabled conditions are not supported")
	}

	// Group node (has combinator + rules)
	if node.Combinator != "" {
		op := ""
		switch strings.ToLower(node.Combinator) {
		case "and":
			op = " && "
		case "or":
			op = " || "
		default:
			return "", fmt.Errorf("unknown combinator: %s", node.Combinator)
		}
		if len(node.Rules) == 0 {
			return "", errors.New("empty condition group")
		}
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
		expr := strings.Join(parts, op)
		if node.Not {
			expr = "!(" + expr + ")"
		}
		return expr, nil
	}

	return leafToCEL(node)
}

// leafToCEL handles a node with field + operator + value. The value is coerced
// to the field's type: the builder often sends numbers as strings, and CEL
// refuses to compare a double with an int.
func leafToCEL(node queryBuilderNode) (string, error) {
	field := node.Field
	if field == "" {
		return "", errors.New("condition has no field")
	}
	typ, ok := fieldTypes[field]
	if !ok {
		return "", fmt.Errorf("unknown field: %s", field)
	}
	if node.ValueSource != "" && node.ValueSource != "value" {
		return "", fmt.Errorf("unsupported value source: %s", node.ValueSource)
	}
	isList := typ == listOfStrings
	isNumber := typ == cel.DoubleType || typ == cel.IntType

	unsupported := fmt.Errorf("operator %s is not valid for field %s", node.Operator, field)
	switch node.Operator {
	case "=", "==", "!=":
		if isList {
			return "", unsupported
		}
		lit, err := celValue(typ, node.Value)
		if err != nil {
			return "", fmt.Errorf("%s: %w", field, err)
		}
		op := "=="
		if node.Operator == "!=" {
			op = "!="
		}
		return fmt.Sprintf("%s %s %s", field, op, lit), nil
	case ">", ">=", "<", "<=":
		if !isNumber {
			return "", unsupported
		}
		lit, err := celValue(typ, node.Value)
		if err != nil {
			return "", fmt.Errorf("%s: %w", field, err)
		}
		return fmt.Sprintf("%s %s %s", field, node.Operator, lit), nil
	case "contains":
		if typ != cel.StringType && !isList {
			return "", unsupported
		}
		lit, err := celValue(cel.StringType, node.Value)
		if err != nil {
			return "", fmt.Errorf("%s: %w", field, err)
		}
		if isList {
			return fmt.Sprintf("%s in %s", lit, field), nil
		}
		return fmt.Sprintf("%s.contains(%s)", field, lit), nil
	case "in":
		switch {
		case isList:
			lit, err := celValue(cel.StringType, node.Value)
			if err != nil {
				return "", fmt.Errorf("%s: %w", field, err)
			}
			return fmt.Sprintf("%s in %s", lit, field), nil
		case typ == cel.StringType:
			lit, err := celStringList(node.Value)
			if err != nil {
				return "", fmt.Errorf("%s: %w", field, err)
			}
			return fmt.Sprintf("%s in %s", field, lit), nil
		default:
			return "", unsupported
		}
	default:
		return "", fmt.Errorf("unknown operator: %s", node.Operator)
	}
}

// celValue renders v as a CEL literal of type typ.
func celValue(typ *cel.Type, v any) (string, error) {
	switch typ {
	case cel.StringType:
		if s, ok := v.(string); ok {
			return strconv.Quote(s), nil
		}
	case cel.BoolType:
		switch val := v.(type) {
		case bool:
			return strconv.FormatBool(val), nil
		case string:
			if val == "true" || val == "false" {
				return val, nil
			}
		}
	case cel.DoubleType, cel.IntType:
		f, ok := v.(float64)
		if s, isString := v.(string); isString {
			parsed, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
			f, ok = parsed, err == nil
		}
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			break
		}
		if typ == cel.DoubleType {
			lit := strconv.FormatFloat(f, 'f', -1, 64)
			if !strings.Contains(lit, ".") {
				lit += ".0"
			}
			return lit, nil
		}
		if f == math.Trunc(f) && math.Abs(f) < 1<<53 {
			return strconv.FormatInt(int64(f), 10), nil
		}
	}
	return "", fmt.Errorf("invalid value %v for type %s", v, typ)
}

// celStringList renders a list value, or the comma-separated form the builder uses.
func celStringList(v any) (string, error) {
	var items []string
	switch val := v.(type) {
	case string:
		for _, item := range strings.Split(val, ",") {
			if item = strings.TrimSpace(item); item != "" {
				items = append(items, item)
			}
		}
	case []any:
		for _, item := range val {
			s, ok := item.(string)
			if !ok {
				return "", fmt.Errorf("invalid list item %v", item)
			}
			items = append(items, s)
		}
	}
	if len(items) == 0 {
		return "", errors.New("value must be a non-empty list")
	}
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = strconv.Quote(item)
	}
	return "[" + strings.Join(quoted, ", ") + "]", nil
}
