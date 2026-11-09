package indirect

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/rules"
	"github.com/guard-spec/guard-spec/internal/sanitizer"
)

// BlockThreshold is the default floor for indirect.score, the same as for
// direct injection.
const BlockThreshold = 0.85

// minCategoryScore matches the fusion layer: below it no category is named.
const minCategoryScore = 0.3

// Verdict is the detector's opinion of one piece of text.
type Verdict struct {
	Source Source  `json:"source"`
	Score  float64 `json:"score"`
	// Category is the detector's category with the source's hint applied:
	// injection found in a tool result or document is indirect_injection, and
	// anything flagged in a tool description is tool_poisoning.
	Category         string   `json:"category,omitempty"`
	DetectorCategory string   `json:"detector_category,omitempty"` // before the hint
	Rules            []string `json:"rules,omitempty"`
	Signals          []string `json:"signals,omitempty"` // MCP poisoning signals (tool descriptions)

	Scores inference.Scores `json:"-"` // the runner's output, for the audit row
}

// Scanner scores untrusted text with the gateway's injection detector.
type Scanner struct {
	Runner *inference.Runner
	// NoCodeCorroboration turns code corroboration off for tool results and
	// documents (TOOL_CODE_CORROBORATION=off; corroborate.go).
	NoCodeCorroboration bool
}

// Adjust is the per-chunk adjustment Score applies to text from src: code
// corroboration for tool results and documents, unless turned off; nil
// otherwise. The gateway passes it to the long path (inference.LongInput)
// when it scores such texts ahead.
func (s Scanner) Adjust(src Source) inference.ChunkAdjust {
	if (src == SourceTool || src == SourceDocument) && !s.NoCodeCorroboration {
		return CorroborateCode
	}
	return nil
}

// Score classifies sanitized text that came from src.
func (s Scanner) Score(ctx context.Context, text string, src Source) (Verdict, error) {
	scores, err := s.Runner.ScanAdjusted(ctx, text, s.Adjust(src))
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{Source: src, Score: float64(scores.Injection.Confidence), Scores: scores}
	if d := scores.Injection.Detail; d != nil {
		v.DetectorCategory, v.Rules = d.Category, d.Rules
	} else if l := scores.Injection.Label; l != "" && l != "BENIGN" && v.Score >= minCategoryScore {
		v.DetectorCategory = l
	}
	v.Category = Hint(src, v.DetectorCategory)
	return v, nil
}

// Hint applies the source's category hint to a detector category.
func Hint(src Source, category string) string {
	if category == "" {
		return ""
	}
	switch src {
	case SourceToolDescription:
		return rules.ToolPoisoning
	case SourceTool, SourceDocument:
		// The text was not written by the user, so an instruction in it is an
		// indirect injection. More specific categories (exfiltration, prompt
		// extraction, ...) are kept.
		if category == rules.DirectInjection {
			return rules.IndirectInjection
		}
	}
	return category
}

// Tool is a tool definition as an MCP server (name, description, inputSchema)
// or an OpenAI request (function.name, .description, .parameters) gives it.
type Tool struct {
	Name        string
	Description string
	Schema      any // decoded JSON schema of the input; may be nil
}

// Field is one description in a tool definition.
type Field struct {
	Path string // "description", or a schema path such as "inputSchema.properties.notes.description"
	Text string
}

// Fields lists the tool's description and every description string nested
// in its schema, in a stable order. schemaKey names the schema in the paths.
func (t Tool) Fields(schemaKey string) ([]Field, error) {
	var out []Field
	if t.Description != "" {
		out = append(out, Field{Path: "description", Text: t.Description})
	}
	if err := walkDescriptions(t.Schema, schemaKey, &out, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// maxSchemaDepth bounds the walk; a deeper schema is refused, not skipped.
const maxSchemaDepth = 32

// ErrSchemaTooDeep means a tool schema nests deeper than we walk.
var ErrSchemaTooDeep = fmt.Errorf("tool schema nests deeper than %d levels", maxSchemaDepth)

func walkDescriptions(node any, path string, out *[]Field, depth int) error {
	if depth > maxSchemaDepth {
		return ErrSchemaTooDeep
	}
	switch n := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := path + "." + k
			if s, ok := n[k].(string); ok {
				if strings.EqualFold(k, "description") && s != "" {
					*out = append(*out, Field{Path: p, Text: s})
				}
				continue
			}
			if err := walkDescriptions(n[k], p, out, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range n {
			if err := walkDescriptions(item, path+"["+strconv.Itoa(i)+"]", out, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// MCP signal weights. A strong signal (a secret path, a hidden-instruction
// tag, a request to hide something from the user, invisible characters) is
// enough to block on its own; weak ones only block together.
const (
	strongSignal = 0.9
	weakSignal   = 0.5
)

var strongSignals = map[string]bool{
	"~/.ssh":                          true,
	"id_rsa":                          true,
	"/etc/shadow":                     true,
	"<important>":                     true,
	"do not mention this to the user": true,
	"send all emails to":              true,
	sanitizer.MCPSignalInvisible:      true,
}

// SignalScore turns MCP poisoning signals into a score: the noisy-OR of
// their weights.
func SignalScore(signals []string) float64 {
	miss := 1.0
	for _, s := range signals {
		w := weakSignal
		if strongSignals[s] {
			w = strongSignal
		}
		miss *= 1 - w
	}
	return 1 - miss
}

// ToolVerdict is the verdict on one tool definition.
type ToolVerdict struct {
	Name string `json:"name"`
	Verdict
	Fields []FieldVerdict `json:"fields,omitempty"` // only with ScoreTool(detail=true): fields that scored or carried signals
}

// FieldVerdict explains one description of a tool.
type FieldVerdict struct {
	Path string `json:"path"`
	Verdict
}

// ScoreTool scores a tool definition: the detector on all its descriptions
// together (sanitized), and CheckMCPDescription's signals on each raw
// description. The score is the larger of the two. With detail, each
// description is also scored alone and those that scored or carried a signal
// are listed. schemaKey names the schema in field paths.
func (s Scanner) ScoreTool(ctx context.Context, t Tool, schemaKey string, detail bool) (ToolVerdict, error) {
	fields, err := t.Fields(schemaKey)
	if err != nil {
		return ToolVerdict{}, err
	}
	tv := ToolVerdict{Name: t.Name}
	var cleaned, signals []string
	seen := map[string]bool{}
	type fieldScan struct {
		text    string
		signals []string
	}
	scans := make([]fieldScan, len(fields))
	for i, f := range fields {
		fieldSignals := sanitizer.MCPSignals(f.Text)
		for _, sig := range fieldSignals {
			if !seen[sig] {
				seen[sig] = true
				signals = append(signals, sig)
			}
		}
		text, _, err := sanitizer.Sanitize(f.Text)
		if err != nil {
			return ToolVerdict{}, fmt.Errorf("%s: %w", f.Path, err)
		}
		scans[i] = fieldScan{text: text, signals: fieldSignals}
		cleaned = append(cleaned, text)
	}
	det, err := s.Score(ctx, strings.Join(cleaned, "\n"), SourceToolDescription)
	if err != nil {
		return ToolVerdict{}, err
	}
	tv.Verdict = mergeSignals(det, signals)
	if !detail {
		return tv, nil
	}
	for i, f := range fields {
		fv, err := s.Score(ctx, scans[i].text, SourceToolDescription)
		if err != nil {
			return ToolVerdict{}, err
		}
		fv = mergeSignals(fv, scans[i].signals)
		if fv.Score >= minCategoryScore || len(fv.Signals) > 0 {
			tv.Fields = append(tv.Fields, FieldVerdict{Path: f.Path, Verdict: fv})
		}
	}
	return tv, nil
}

// mergeSignals raises a detector verdict to the signal score.
func mergeSignals(v Verdict, signals []string) Verdict {
	v.Signals = signals
	if sig := SignalScore(signals); sig > v.Score {
		v.Score = sig
	}
	if v.Category == "" && v.Score >= minCategoryScore {
		v.Category = rules.ToolPoisoning
	}
	return v
}
