package policy

// Rule conditions as text. The stored form of a condition stays the
// react-querybuilder tree; text is only an editing format:
//
//   - ParseCondition turns text into a tree. The text goes through the cel-go
//     parser for its syntax tree only; it is never type-checked, compiled or
//     run. The walk below accepts a small subset and rebuilds every leaf as a
//     typed {field, operator, value}, so the CEL that runs is always the one
//     JSONASTToCEL generates from the tree.
//   - FormatCondition turns a tree into text: the JSONASTToCEL output with the
//     parentheses removed that grouping does not need.
//
// Parentheses carry structure: a parenthesized group stays a group of its own,
// so parse(format(tree)) gives the tree back (in canonical form, see
// canonical) and format(parse(text)) is stable.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/antlr4-go/antlr/v4"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/parser"
	"github.com/google/cel-go/parser/gen"
)

// MaxConditionText is the longest condition text ParseCondition accepts, in
// characters (Unicode code points).
const MaxConditionText = 4096

// maxParseDepth bounds the parser's recursion; conditions never nest deeply.
const maxParseDepth = 64

// ParseError is a condition text that ParseCondition refused. Position is the
// 0-based offset of the problem in the text, in characters (code points).
type ParseError struct {
	Message  string
	Position int
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s (at position %d)", e.Message, e.Position)
}

// condNode is a condition tree node: a group when Combinator is set, else a leaf.
type condNode struct {
	Combinator string
	Not        bool
	Rules      []*condNode
	Field      string
	Operator   string
	Value      any // float64, string, bool or []any of strings
}

func (n *condNode) isGroup() bool { return n.Combinator != "" }

type groupJSON struct {
	Combinator string `json:"combinator"`
	Not        bool   `json:"not,omitempty"`
	Rules      []any  `json:"rules"`
}

type leafJSON struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    any    `json:"value"`
}

// plain returns the react-querybuilder shape of n.
func (n *condNode) plain() any {
	if !n.isGroup() {
		return leafJSON{n.Field, n.Operator, n.Value}
	}
	rules := make([]any, len(n.Rules))
	for i, r := range n.Rules {
		rules[i] = r.plain()
	}
	return groupJSON{n.Combinator, n.Not, rules}
}

// marshalTree encodes a tree without HTML escaping, so that > stays readable.
func marshalTree(n *condNode) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(n.plain()); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

func newGroup(combinator string, rules ...*condNode) *condNode {
	return &condNode{Combinator: combinator, Rules: rules}
}

// ── Tree to text ─────────────────────────────────────────────────────────────

// FormatCondition renders a stored condition tree as text. It refuses a tree
// JSONASTToCEL refuses, including one that names a removed field.
func FormatCondition(raw json.RawMessage) (string, error) {
	return formatCondition(raw, false)
}

// FormatStoredCondition is FormatCondition that also renders removed fields,
// for showing rules saved before a field was removed.
func FormatStoredCondition(raw json.RawMessage) (string, error) {
	return formatCondition(raw, true)
}

func formatCondition(raw json.RawMessage, legacy bool) (string, error) {
	root, err := canonicalTree(raw, legacy)
	if err != nil {
		return "", err
	}
	return formatGroup(root, legacy)
}

// CanonicalCondition returns the canonical form of a condition tree: the tree
// ParseCondition returns for its FormatCondition text.
func CanonicalCondition(raw json.RawMessage) (json.RawMessage, error) {
	root, err := canonicalTree(raw, false)
	if err != nil {
		return nil, err
	}
	return marshalTree(root)
}

// canonicalTree decodes a tree into canonical form:
//   - the root is a group (a leaf root becomes a one-rule "and" group);
//   - a group with one rule uses "and" (with one rule the combinator means nothing);
//   - a root that only wraps a negated group is that group;
//   - a leaf has the canonical operator and a value of the field's type.
func canonicalTree(raw json.RawMessage, legacy bool) (*condNode, error) {
	// The conversion validates the whole tree with the same rules as storage.
	if _, err := jsonASTToCEL(raw, legacy); err != nil {
		return nil, err
	}
	root, err := decodeNode(raw, legacy)
	if err != nil {
		return nil, err
	}
	if !root.isGroup() {
		root = newGroup("and", root)
	}
	root = canonicalize(root)
	if !root.Not && len(root.Rules) == 1 && root.Rules[0].isGroup() && root.Rules[0].Not {
		root = root.Rules[0]
	}
	return root, nil
}

func canonicalize(n *condNode) *condNode {
	if !n.isGroup() {
		return n
	}
	for i, c := range n.Rules {
		n.Rules[i] = canonicalize(c)
	}
	if len(n.Rules) == 1 {
		n.Combinator = "and"
	}
	return n
}

func decodeNode(raw json.RawMessage, legacy bool) (*condNode, error) {
	var node queryBuilderNode
	if err := json.Unmarshal(raw, &node); err != nil {
		return nil, err
	}
	if node.Combinator != "" {
		g := newGroup(strings.ToLower(node.Combinator))
		g.Not = node.Not
		for _, r := range node.Rules {
			c, err := decodeNode(r, legacy)
			if err != nil {
				return nil, err
			}
			g.Rules = append(g.Rules, c)
		}
		return g, nil
	}
	return canonicalLeaf(node, legacy)
}

// canonicalLeaf returns a leaf that leafToCEL renders exactly as it renders node.
func canonicalLeaf(node queryBuilderNode, legacy bool) (*condNode, error) {
	typ, err := lookupField(node.Field, legacy)
	if err != nil {
		return nil, err
	}
	leaf := &condNode{Field: node.Field, Operator: node.Operator}
	switch {
	case node.Operator == "==":
		leaf.Operator = "="
	case typ == listOfStrings && node.Operator == "in":
		leaf.Operator = "contains" // both render as "x" in field
	}
	switch {
	case leaf.Operator == "in":
		items, err := stringItems(node.Value)
		if err != nil {
			return nil, err
		}
		leaf.Value = items
	case typ == listOfStrings || typ == cel.StringType:
		s, ok := node.Value.(string)
		if !ok {
			return nil, fmt.Errorf("%s: value must be a string", node.Field)
		}
		leaf.Value = s
	case typ == cel.BoolType:
		switch v := node.Value.(type) {
		case bool:
			leaf.Value = v
		case string:
			leaf.Value = v == "true"
		}
	default:
		f, err := numberValue(node.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", node.Field, err)
		}
		leaf.Value = f
	}
	return leaf, nil
}

func lookupField(field string, legacy bool) (*cel.Type, error) {
	if typ, ok := fieldTypes[field]; ok {
		return typ, nil
	}
	if typ, ok := removedFields[field]; ok {
		if legacy {
			return typ, nil
		}
		return nil, fmt.Errorf("%s: %w", field, ErrRemovedField)
	}
	return nil, fmt.Errorf("unknown field: %s", field)
}

// stringItems returns the items celStringList renders.
func stringItems(v any) ([]any, error) {
	var items []any
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
				return nil, fmt.Errorf("invalid list item %v", item)
			}
			items = append(items, s)
		}
	}
	if len(items) == 0 {
		return nil, errors.New("value must be a non-empty list")
	}
	return items, nil
}

func numberValue(v any) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil {
			return f, nil
		}
	}
	return 0, fmt.Errorf("invalid number %v", v)
}

func joiner(combinator string) string {
	if combinator == "or" {
		return " || "
	}
	return " && "
}

func formatGroup(g *condNode, legacy bool) (string, error) {
	parts := make([]string, 0, len(g.Rules))
	for _, c := range g.Rules {
		s, err := formatChild(c, g, legacy)
		if err != nil {
			return "", err
		}
		parts = append(parts, s)
	}
	body := strings.Join(parts, joiner(g.Combinator))
	if g.Not {
		return "!(" + body + ")", nil
	}
	return body, nil
}

// formatChild drops the parentheses of an "and" group of two or more rules
// inside an "or" group of two or more rules: && binds tighter than ||, and the
// parser reads an unparenthesized && chain inside || as a group of its own.
// Every other group keeps its parentheses, since they make it a group.
func formatChild(c, parent *condNode, legacy bool) (string, error) {
	if !c.isGroup() {
		return leafToCEL(queryBuilderNode{Field: c.Field, Operator: c.Operator, Value: c.Value}, legacy)
	}
	s, err := formatGroup(c, legacy)
	if err != nil {
		return "", err
	}
	if c.Not {
		return s, nil
	}
	if parent.Combinator == "or" && len(parent.Rules) > 1 && c.Combinator == "and" && len(c.Rules) > 1 {
		return s, nil
	}
	return "(" + s + ")", nil
}

// ── Text to tree ─────────────────────────────────────────────────────────────

var textParser = func() *parser.Parser {
	p, err := parser.NewParser(
		parser.MaxRecursionDepth(maxParseDepth),
		parser.ExpressionSizeCodePointLimit(MaxConditionText),
		parser.ErrorReportingLimit(5),
	)
	if err != nil {
		panic(err)
	}
	return p
}()

// ParseCondition parses condition text into a canonical condition tree. A
// refusal is a *ParseError. The tree is also checked with JSONASTToCEL; the
// caller still validates the CEL with Engine.ValidateCEL, as for any tree.
func ParseCondition(text string) (json.RawMessage, error) {
	n := utf8.RuneCountInString(text)
	if n > MaxConditionText {
		return nil, &ParseError{Message: fmt.Sprintf("condition is longer than %d characters", MaxConditionText),
			Position: MaxConditionText}
	}
	if strings.TrimSpace(text) == "" {
		return nil, &ParseError{Message: "condition is empty"}
	}
	src := common.NewTextSource(text)
	tree, errs := textParser.Parse(src)
	if errs != nil && len(errs.GetErrors()) > 0 {
		first := errs.GetErrors()[0]
		pos, ok := src.LocationOffset(first.Location)
		if !ok || pos < 0 {
			pos = 0
		}
		return nil, &ParseError{Message: "syntax error: " + first.Message, Position: int(pos)}
	}
	w := newWalker(text, tree.SourceInfo())
	root, err := w.root(tree.Expr())
	if err != nil {
		return nil, err
	}
	raw, err := marshalTree(root)
	if err != nil {
		return nil, err
	}
	if _, err := JSONASTToCEL(raw); err != nil {
		return nil, &ParseError{Message: err.Error()}
	}
	return raw, nil
}

// walker turns the parsed expression into a tree. Parentheses are not in the
// syntax tree, so it finds them in the token stream: a node is wrapped once
// for each pair of grouping parentheses directly around its tokens.
type walker struct {
	info  *ast.SourceInfo
	toks  []antlr.Token
	at    map[int]int // code point offset -> token index
	match map[int]int // index of ( [ { -> index of the closing token, and back
	spans map[int64]tokenSpan
}

func newWalker(text string, info *ast.SourceInfo) *walker {
	lexer := gen.NewCELLexer(antlr.NewInputStream(text))
	lexer.RemoveErrorListeners()
	w := &walker{info: info, at: map[int]int{}, match: map[int]int{}, spans: map[int64]tokenSpan{}}
	var stack []int
	for _, t := range lexer.GetAllTokens() {
		if t.GetChannel() != antlr.TokenDefaultChannel {
			continue
		}
		i := len(w.toks)
		w.toks = append(w.toks, t)
		w.at[t.GetStart()] = i
		switch t.GetTokenType() {
		case gen.CELLexerLPAREN, gen.CELLexerLBRACKET, gen.CELLexerLBRACE:
			stack = append(stack, i)
		case gen.CELLexerRPAREN, gen.CELLexerRPRACKET, gen.CELLexerRBRACE:
			if len(stack) > 0 {
				open := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				w.match[open], w.match[i] = i, open
			}
		}
	}
	return w
}

type tokenSpan struct{ lo, hi, depth int }

// own returns the token index of e's own token (an operator, a name, the
// opening bracket of a call or list), or -1. The parser records it as e's
// offset; a literal also records its last token (a sign, then the number).
func (w *walker) own(e ast.Expr) (int, int) {
	r, ok := w.info.GetOffsetRange(e.ID())
	if !ok {
		return -1, -1
	}
	lo, okLo := w.at[int(r.Start)]
	hi, okHi := w.at[int(r.Stop)]
	switch {
	case !okLo && !okHi:
		return -1, -1
	case !okLo:
		lo = hi
	case !okHi:
		hi = lo
	}
	return lo, hi
}

// outer returns the token span of e with the grouping parentheses directly
// around it, and how many pairs there are.
func (w *walker) outer(e ast.Expr) tokenSpan {
	if s, ok := w.spans[e.ID()]; ok {
		return s
	}
	lo, hi := math.MaxInt, -1
	add := func(a, b int) {
		if a >= 0 {
			lo, hi = min(lo, a), max(hi, b)
		}
	}
	if a, b := w.own(e); a >= 0 {
		add(a, b)
		for _, i := range []int{a, b} {
			if m, ok := w.match[i]; ok && m > i {
				add(i, m) // a call's or list's closing bracket
				if w.toks[i].GetTokenType() == gen.CELLexerLPAREN && i > 0 &&
					w.toks[i-1].GetTokenType() == gen.CELLexerIDENTIFIER {
					add(i-1, i) // the function or method name
				}
			}
		}
	}
	var children []ast.Expr
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		if call.IsMemberFunction() {
			children = append(children, call.Target())
		}
		children = append(children, call.Args()...)
	case ast.SelectKind:
		children = append(children, e.AsSelect().Operand())
	case ast.ListKind:
		children = append(children, e.AsList().Elements()...)
	}
	for _, c := range children {
		s := w.outer(c)
		add(s.lo, s.hi)
	}
	s := tokenSpan{lo: lo, hi: hi}
	if hi >= 0 {
		for s.lo > 0 && s.hi+1 < len(w.toks) &&
			w.toks[s.lo-1].GetTokenType() == gen.CELLexerLPAREN &&
			w.toks[s.hi+1].GetTokenType() == gen.CELLexerRPAREN && w.match[s.lo-1] == s.hi+1 {
			s.depth++
			s.lo, s.hi = s.lo-1, s.hi+1
		}
	}
	w.spans[e.ID()] = s
	return s
}

// depth counts the grouping parentheses directly around e.
func (w *walker) depth(e ast.Expr) int { return w.outer(e).depth }

// pos is the offset of e's first token (inside its parentheses).
func (w *walker) pos(e ast.Expr) int {
	s := w.outer(e)
	if s.hi < 0 {
		return 0
	}
	return w.toks[s.lo+s.depth].GetStart()
}

// ownPos is the offset of e's own token, such as its operator.
func (w *walker) ownPos(e ast.Expr) int {
	if i, _ := w.own(e); i >= 0 {
		return w.toks[i].GetStart()
	}
	return w.pos(e)
}

func (w *walker) fail(e ast.Expr, format string, args ...any) error {
	return &ParseError{Message: fmt.Sprintf(format, args...), Position: w.pos(e)}
}

func callName(e ast.Expr) string {
	if e.Kind() != ast.CallKind {
		return ""
	}
	return e.AsCall().FunctionName()
}

func isChain(e ast.Expr) bool {
	name := callName(e)
	return name == operators.LogicalAnd || name == operators.LogicalOr
}

func (w *walker) root(e ast.Expr) (*condNode, error) {
	d := w.depth(e)
	if callName(e) == operators.LogicalNot && d == 0 {
		return w.not(e)
	}
	return w.body(e, d)
}

// body reads the inside of a pair of parentheses (or the whole text): a chain
// is the group itself, anything else is a group of one rule.
func (w *walker) body(e ast.Expr, d int) (*condNode, error) {
	if d == 0 && isChain(e) {
		return w.chain(e)
	}
	c, err := w.child(e, d)
	if err != nil {
		return nil, err
	}
	return newGroup("and", c), nil
}

// child reads an operand that sits inside d pairs of parentheses.
func (w *walker) child(e ast.Expr, d int) (*condNode, error) {
	if d > 0 {
		return w.body(e, d-1)
	}
	switch {
	case isChain(e):
		return w.chain(e)
	case callName(e) == operators.LogicalNot:
		return w.not(e)
	default:
		return w.leaf(e)
	}
}

// chain flattens a run of the same operator into one group. An operand in
// parentheses, or a chain of the other operator, becomes a group of its own.
func (w *walker) chain(e ast.Expr) (*condNode, error) {
	op := callName(e)
	g := newGroup("and")
	if op == operators.LogicalOr {
		g.Combinator = "or"
	}
	var collect func(x ast.Expr) error
	collect = func(x ast.Expr) error {
		d := w.depth(x)
		if callName(x) == op && d == 0 {
			for _, a := range x.AsCall().Args() {
				if err := collect(a); err != nil {
					return err
				}
			}
			return nil
		}
		c, err := w.child(x, d)
		if err != nil {
			return err
		}
		g.Rules = append(g.Rules, c)
		return nil
	}
	for _, a := range e.AsCall().Args() {
		if err := collect(a); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// not reads !operand. The first pair of parentheses after ! belongs to the !.
func (w *walker) not(e ast.Expr) (*condNode, error) {
	args := e.AsCall().Args()
	if len(args) != 1 {
		return nil, w.fail(e, "! takes one operand")
	}
	d := w.depth(args[0])
	if d > 0 {
		d--
	}
	g, err := w.body(args[0], d)
	if err != nil {
		return nil, err
	}
	g.Not = true
	return g, nil
}

var comparisons = map[string]string{
	operators.Equals:        "=",
	operators.NotEquals:     "!=",
	operators.Less:          "<",
	operators.LessEquals:    "<=",
	operators.Greater:       ">",
	operators.GreaterEquals: ">=",
}

var methods = map[string]string{
	"contains":   "contains",
	"startsWith": "beginsWith",
	"endsWith":   "endsWith",
}

// fieldOf returns the schema field e names, or "" when e is not a field path.
func (w *walker) fieldOf(e ast.Expr) (string, *cel.Type, error) {
	var parts []string
	x := e
	for x.Kind() == ast.SelectKind {
		sel := x.AsSelect()
		if sel.IsTestOnly() {
			return "", nil, nil
		}
		parts = append([]string{sel.FieldName()}, parts...)
		x = sel.Operand()
	}
	if x.Kind() != ast.IdentKind {
		return "", nil, nil
	}
	name := strings.Join(append([]string{x.AsIdent()}, parts...), ".")
	typ, err := lookupField(name, false)
	if err != nil {
		return "", nil, w.fail(e, "%s", err.Error())
	}
	return name, typ, nil
}

// literal returns e's value as float64, string or bool.
func (w *walker) literal(e ast.Expr) (any, bool) {
	if e.Kind() != ast.LiteralKind {
		return nil, false
	}
	switch v := e.AsLiteral().Value().(type) {
	case float64:
		return v, true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case string:
		return v, true
	case bool:
		return v, true
	}
	return nil, false
}

func typeLabel(t *cel.Type) string { return typeName(t) }

// value checks a literal against the field's type.
func (w *walker) value(field string, typ *cel.Type, lit ast.Expr) (any, error) {
	if lit.Kind() != ast.LiteralKind {
		if f, _, _ := w.fieldOf(lit); f != "" {
			return nil, w.fail(lit, "compare %s with a literal value, not with another field", field)
		}
		return nil, w.unsupported(lit)
	}
	v, _ := w.literal(lit) // nil for null and bytes, refused below
	switch typ {
	case cel.DoubleType, cel.IntType:
		f, ok := v.(float64)
		if !ok {
			return nil, w.fail(lit, "%s is a number", field)
		}
		if typ == cel.IntType && (f != math.Trunc(f) || math.Abs(f) >= 1<<53) {
			return nil, w.fail(lit, "%s is a whole number", field)
		}
		return f, nil
	case cel.StringType:
		if _, ok := v.(string); !ok {
			return nil, w.fail(lit, "%s is a string", field)
		}
	case cel.BoolType:
		if _, ok := v.(bool); !ok {
			return nil, w.fail(lit, "%s is true or false", field)
		}
	}
	return v, nil
}

// leaf reads one condition: a comparison, a membership test, a string method
// or a bool field on its own.
func (w *walker) leaf(e ast.Expr) (*condNode, error) {
	switch e.Kind() {
	case ast.SelectKind, ast.IdentKind:
		field, typ, err := w.fieldOf(e)
		if err != nil {
			return nil, err
		}
		if field == "" {
			return nil, w.fail(e, "unsupported expression")
		}
		if typ != cel.BoolType {
			return nil, w.fail(e, "%s is a %s; compare it with a value", field, typeLabel(typ))
		}
		return &condNode{Field: field, Operator: "=", Value: true}, nil
	case ast.CallKind:
	case ast.LiteralKind:
		return nil, w.fail(e, "a constant is not a condition")
	default:
		return nil, w.fail(e, "unsupported expression")
	}
	call := e.AsCall()
	name := call.FunctionName()
	args := call.Args()
	if call.IsMemberFunction() {
		op, ok := methods[name]
		if !ok {
			return nil, w.unsupported(e)
		}
		field, typ, err := w.fieldOf(call.Target())
		if err != nil {
			return nil, err
		}
		if field == "" || typ != cel.StringType {
			return nil, w.fail(e, "%s applies to a string field", name)
		}
		if len(args) != 1 {
			return nil, w.fail(e, "%s takes one string", name)
		}
		v, err := w.value(field, cel.StringType, args[0])
		if err != nil {
			return nil, err
		}
		return &condNode{Field: field, Operator: op, Value: v}, nil
	}
	if op, ok := comparisons[name]; ok && len(args) == 2 {
		field, typ, err := w.fieldOf(args[0])
		if err != nil {
			return nil, err
		}
		if field == "" {
			if args[0].Kind() != ast.LiteralKind {
				return nil, w.unsupported(args[0])
			}
			if f, _, _ := w.fieldOf(args[1]); f != "" {
				return nil, w.fail(e, "put the field on the left: %s %s value", f, op)
			}
			return nil, w.fail(args[0], "a comparison needs a field on the left")
		}
		if typ == listOfStrings {
			return nil, w.fail(e, "%s is a list; use \"value\" in %s", field, field)
		}
		if op != "=" && op != "!=" && typ != cel.DoubleType && typ != cel.IntType {
			return nil, w.fail(e, "%s is a %s; only = and != apply", field, typeLabel(typ))
		}
		v, err := w.value(field, typ, args[1])
		if err != nil {
			return nil, err
		}
		return &condNode{Field: field, Operator: op, Value: v}, nil
	}
	if name == operators.In && len(args) == 2 {
		return w.in(e, args[0], args[1])
	}
	return nil, w.unsupported(e)
}

// unsupported explains why e cannot be part of a condition.
func (w *walker) unsupported(e ast.Expr) error {
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		name := call.FunctionName()
		if call.IsMemberFunction() {
			pos := w.ownPos(e)
			if i, _ := w.own(e); i > 0 {
				pos = w.toks[i-1].GetStart() // the method name, before its (
			}
			return &ParseError{Position: pos,
				Message: fmt.Sprintf("method %s is not supported; use contains, startsWith or endsWith", name)}
		}
		if op, ok := operatorText(name); ok {
			return &ParseError{Position: w.ownPos(e), Message: fmt.Sprintf("operator %s is not supported here", op)}
		}
		return w.fail(e, "function %s is not supported", name)
	case ast.LiteralKind:
		return w.fail(e, "a constant is not a condition")
	default:
		return w.fail(e, "unsupported expression")
	}
}

// in reads field in ["a", "b"] (a string field) and "a" in field (a list field).
func (w *walker) in(e, left, right ast.Expr) (*condNode, error) {
	if field, typ, err := w.fieldOf(left); err != nil {
		return nil, err
	} else if field != "" {
		if typ != cel.StringType {
			return nil, w.fail(e, "%s is a %s; in applies to a string field", field, typeLabel(typ))
		}
		if right.Kind() != ast.ListKind || len(right.AsList().Elements()) == 0 {
			return nil, w.fail(right, "in needs a non-empty list of strings, like [\"a\", \"b\"]")
		}
		var items []any
		for _, el := range right.AsList().Elements() {
			v, ok := w.literal(el)
			s, isString := v.(string)
			if !ok || !isString {
				return nil, w.fail(el, "in needs a list of strings")
			}
			items = append(items, s)
		}
		return &condNode{Field: field, Operator: "in", Value: items}, nil
	}
	field, typ, err := w.fieldOf(right)
	if err != nil {
		return nil, err
	}
	if field == "" || typ != listOfStrings {
		return nil, w.fail(e, "in needs a string field on the left or a list field on the right")
	}
	v, ok := w.literal(left)
	if _, isString := v.(string); !ok || !isString {
		return nil, w.fail(left, "the value in front of in must be a string")
	}
	return &condNode{Field: field, Operator: "contains", Value: v}, nil
}

// operatorText returns how an operator function is written.
func operatorText(name string) (string, bool) {
	switch name {
	case operators.Conditional:
		return "?:", true
	case operators.Index, operators.OptIndex:
		return "[]", true
	case operators.OptSelect:
		return ".?", true
	case operators.Negate:
		return "-", true
	case operators.LogicalNot:
		return "!", true
	}
	if d, ok := operators.FindReverse(name); ok && d != "" {
		return d, true
	}
	if strings.HasPrefix(name, "_") || strings.HasPrefix(name, "@") {
		return strings.Trim(name, "_@"), true
	}
	return "", false
}

// errNotParseError guards the type of errors ParseCondition returns.
var _ error = (*ParseError)(nil)

// AsParseError returns err as a *ParseError when it is one.
func AsParseError(err error) (*ParseError, bool) {
	var pe *ParseError
	ok := errors.As(err, &pe)
	return pe, ok
}
