package policy

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
)

// TraceEntry is the outcome of one rule in a simulation.
type TraceEntry struct {
	PolicyID *uuid.UUID `json:"policy_id"` // nil for unsaved rules
	RuleID   uuid.UUID  `json:"rule_id"`
	RuleName string     `json:"rule_name"`
	Matched  bool       `json:"matched"`
	Action   Action     `json:"action"`
	Error    string     `json:"error"`
}

// SimPolicy is a policy to simulate. ID is nil for an unsaved rule list.
type SimPolicy struct {
	ID    *uuid.UUID
	Rules []Rule
}

// Simulate runs every rule of policies, in order, and reports each outcome.
// The decision is the one the gateway would take: the first allow, block or
// route match. The gateway compiles every policy before it evaluates any and
// stops at the decision, so failed is set when a rule does not compile, or
// when a rule up to the decision fails to evaluate (or the request's cost
// budget runs out there): the gateway would then refuse the request (503).
// Rules after the decision are evaluated for the trace only.
//
// Nothing is cached: unsaved rules must not displace the gateway's programs.
func (e *Engine) Simulate(ctx context.Context, policies []SimPolicy, v *Vars) (trace []TraceEntry, decision Decision, failed error) {
	type compiled struct {
		entry   int
		program cel.Program
	}
	trace = []TraceEntry{}
	var programs []compiled
	for _, p := range policies {
		for _, rule := range p.Rules {
			t := TraceEntry{PolicyID: p.ID, RuleID: rule.ID, RuleName: rule.Name, Action: rule.Action}
			var prg cel.Program
			expr, err := jsonASTToCEL(rule.Condition, true)
			if err == nil {
				prg, err = e.compileExpr(expr)
			}
			if err == nil {
				err = checkAction(rule.Action)
			}
			if err != nil {
				t.Error = err.Error()
				if failed == nil {
					failed = fmt.Errorf("rule %q: %w", rule.Name, err)
				}
			}
			programs = append(programs, compiled{entry: len(trace), program: prg})
			trace = append(trace, t)
		}
	}

	activation := v.toActivation()
	decision = DefaultAllow
	decided := false
	var spent uint64
	for i, c := range programs {
		t := &trace[c.entry]
		if c.program == nil {
			continue
		}
		rule := ruleAt(policies, i)
		out, details, err := c.program.ContextEval(ctx, activation)
		if err == nil && (details == nil || details.ActualCost() == nil) {
			err = errors.New("evaluation cost not tracked")
		}
		if err == nil && !decided {
			spent += *details.ActualCost()
			if spent > e.costBudget {
				err = ErrCostBudget
			}
		}
		var matched, ok bool
		if err == nil {
			if matched, ok = out.Value().(bool); !ok {
				err = errors.New("result is not a bool")
			}
		}
		if err != nil {
			t.Error = err.Error()
			if !decided && failed == nil {
				failed = fmt.Errorf("rule %q: %w", rule.Name, err)
			}
			continue
		}
		t.Matched = matched
		if !matched || decided {
			continue
		}
		if rule.Action == ActionLog {
			decision.Logged = append(decision.Logged, rule.ID)
			continue
		}
		decided = true
		decision = Decision{Matched: true, Action: rule.Action, RuleID: rule.ID, RuleName: rule.Name,
			RouteTarget: rule.RouteTarget, Logged: decision.Logged}
	}
	return trace, decision, failed
}

// ruleAt returns the i-th rule across policies.
func ruleAt(policies []SimPolicy, i int) *Rule {
	for _, p := range policies {
		if i < len(p.Rules) {
			return &p.Rules[i]
		}
		i -= len(p.Rules)
	}
	return nil
}

// VarsFromMap builds rule inputs from field names, for the simulator. Fields
// that are not given keep their zero value. Numbers come as JSON numbers.
func VarsFromMap(m map[string]any) (*Vars, error) {
	v := &Vars{}
	for name, raw := range m {
		typ, err := lookupField(name, false)
		if err != nil {
			return nil, err
		}
		var (
			f float64
			s string
			b bool
			l []string
		)
		switch typ {
		case cel.DoubleType, cel.IntType:
			n, ok := raw.(float64)
			if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
				return nil, fmt.Errorf("%s must be a number", name)
			}
			if typ == cel.IntType && (n != math.Trunc(n) || math.Abs(n) > math.MaxInt32) {
				return nil, fmt.Errorf("%s must be a whole number", name)
			}
			f = n
		case cel.StringType:
			str, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a string", name)
			}
			s = str
		case cel.BoolType:
			val, ok := raw.(bool)
			if !ok {
				return nil, fmt.Errorf("%s must be true or false", name)
			}
			b = val
		case listOfStrings:
			items, ok := raw.([]any)
			if !ok {
				return nil, fmt.Errorf("%s must be a list of strings", name)
			}
			l = make([]string, 0, len(items))
			for _, item := range items {
				str, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("%s must be a list of strings", name)
				}
				l = append(l, str)
			}
		}
		switch name {
		case "request.model":
			v.RequestModel = s
		case "request.tenant_id":
			v.RequestTenantID = s
		case "request.tokens":
			v.RequestTokens = int(f)
		case "injection.score":
			v.InjectionScore = f
		case "injection.label":
			v.InjectionLabel = s
		case "injection.category":
			v.InjectionCat = s
		case "scores.l1":
			v.ScoreL1 = f
		case "scores.l2":
			v.ScoreL2 = f
		case "scores.l3":
			v.ScoreL3 = f
		case "indirect.score":
			v.IndirectScore = f
		case "indirect.source":
			v.IndirectSource = s
		case "injection.source_role":
			v.SourceRole = s
		case "conversation.score":
			v.ConversationScore = f
		case "anomaly.score":
			v.AnomalyScore = float32(f)
		case "anomaly.has_tag_chars":
			v.AnomalyHasTagChars = b
		case "anomaly.has_bidi":
			v.AnomalyHasBidi = b
		case "mcp.is_tool_response":
			v.IsMCPResponse = b
		case "input.pii.kinds":
			v.InputPIIKinds = l
		case "input.pii.count":
			if f < 0 {
				return nil, fmt.Errorf("%s must not be negative", name)
			}
			v.InputPIICount = int(f)
		default:
			return nil, fmt.Errorf("field %s cannot be simulated", name)
		}
	}
	return v, nil
}
