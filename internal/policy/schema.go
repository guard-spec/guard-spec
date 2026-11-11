package policy

import (
	"sort"

	"github.com/google/cel-go/cel"
)

// SchemaField describes one variable a rule condition can name.
type SchemaField struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // double, int, string, bool or list
	Description string   `json:"description"`
	Values      []string `json:"values,omitempty"` // known values of a string field
}

// Schema is what a rule editor needs: the fields, the operators each field
// type accepts and the actions. GET /v1/policy/schema returns it.
type Schema struct {
	Fields    []SchemaField       `json:"fields"`
	Operators map[string][]string `json:"operators"`
	Actions   []Action            `json:"actions"`
}

// operatorsByType is exactly what leafToCEL accepts for each field type, with
// "=" for equality ("==" is also accepted on input).
var operatorsByType = map[string][]string{
	"double": {"=", "!=", ">", ">=", "<", "<="},
	"int":    {"=", "!=", ">", ">=", "<", "<="},
	"string": {"=", "!=", "contains", "beginsWith", "endsWith", "in"},
	"bool":   {"=", "!="},
	"list":   {"contains", "in"},
}

var fieldDescriptions = map[string]string{
	"request.model":         "Model named in the request body.",
	"request.tenant_id":     "Organization id of the API key.",
	"request.tokens":        "Estimated request size in tokens (body bytes / 4).",
	"injection.score":       "Fused prompt-injection score, 0 to 1.",
	"injection.label":       "Top injection category, or BENIGN.",
	"injection.category":    "Top injection category; empty when nothing matched.",
	"scores.l1":             "Calibrated L1 (rules) injection score, 0 to 1.",
	"scores.l2":             "Calibrated L2 (classifier) injection score; -1 when the layer did not run.",
	"scores.l3":             "Calibrated L3 (similarity) injection score; -1 when the layer did not run.",
	"indirect.score":        "Largest injection score over tool results, documents and tool descriptions; 0 when there were none.",
	"indirect.source":       "Source of the strongest untrusted part; empty when there were none.",
	"injection.source_role": "Role of the text with the strongest injection finding; conversation for the conversation window.",
	"conversation.score":    "Injection score of the most recent user turns joined (the conversation window), 0 to 1; 0 when there was none.",
	"anomaly.score":         "Encoding-anomaly score of the sanitizer, 0 to 1.",
	"anomaly.has_tag_chars": "The text contained Unicode tag characters.",
	"anomaly.has_bidi":      "The text contained bidirectional control characters.",
	"mcp.is_tool_response":  "The request carries a tool (MCP) result message.",
	"input.pii.kinds":       "Kinds of personal data in the request text (user turns, tool results, documents; not system prompts): email, phone, card, cccd, ipv4. Pattern checks, not names or addresses. Empty unless the org turned on Detect personal data in requests.",
	"input.pii.count":       "How many values of personal data input.pii.kinds counts, all kinds together; 0 unless the org turned the check on.",
	"input.unscanned.kinds": "Kinds of parts the gateway forwards but cannot read, so they are not checked for injection: image, file, audio, other. Counted in the turns the gateway scans.",
	"input.unscanned.count": "How many such parts the request has, all kinds together.",
	"input.pdf.count":       "How many PDF parts the request has (inline documents and file references), in the turns the gateway scans.",
	"input.pdf.scanned":     "How many of those PDFs the gateway read: text extracted and scanned as a document. 0 when PDF_EXTRACT is off.",
	"input.pdf.reasons":     "Why the other PDFs were not read: no_text (no text layer), encrypted, damaged, timeout, over_limit, internal, remote (a url or file id the gateway cannot fetch). Such PDFs are unscanned parts.",
}

var categoryValues = []string{"direct_injection", "indirect_injection", "jailbreak", "prompt_extraction",
	"data_exfiltration", "tool_poisoning", "obfuscation"}

var fieldValues = map[string][]string{
	"injection.category":    categoryValues,
	"injection.label":       append([]string{"BENIGN"}, categoryValues...),
	"indirect.source":       {"tool", "document", "tool_description"},
	"injection.source_role": {"user", "system", "assistant", "tool", "tool_description", "conversation"},
	"input.pii.kinds":       {"email", "phone", "card", "cccd", "ipv4"},                                         // outputguard.PIIKinds
	"input.unscanned.kinds": {"image", "file", "audio", "other"},                                                // indirect.UnscannedKinds
	"input.pdf.reasons":     {"no_text", "encrypted", "damaged", "timeout", "over_limit", "internal", "remote"}, // indirect.PDFReasons
}

// typeName maps a CEL type to the schema's type name.
func typeName(t *cel.Type) string {
	switch t {
	case cel.DoubleType:
		return "double"
	case cel.IntType:
		return "int"
	case cel.BoolType:
		return "bool"
	case cel.StringType:
		return "string"
	default:
		return "list"
	}
}

// RuleSchema returns the fields (without removed ones), operators and actions.
func RuleSchema() Schema {
	fields := make([]SchemaField, 0, len(fieldTypes))
	for name, typ := range fieldTypes {
		fields = append(fields, SchemaField{Name: name, Type: typeName(typ),
			Description: fieldDescriptions[name], Values: fieldValues[name]})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	ops := make(map[string][]string, len(operatorsByType))
	for k, v := range operatorsByType {
		ops[k] = append([]string(nil), v...)
	}
	return Schema{Fields: fields, Operators: ops, Actions: append([]Action(nil), Actions...)}
}
