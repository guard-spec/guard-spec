package evalset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/giaplee/guard-spec/internal/indirect"
	"github.com/giaplee/guard-spec/internal/inference"
	"github.com/giaplee/guard-spec/internal/sanitizer"
)

// Input paths of cmd/eval -path.
const (
	PathDirect = "direct" // every row as a user message (Run)
	PathTool   = "tool"   // every row as untrusted content (RunIndirect)
)

// toolDefinition recognizes a row that is a tool definition: an MCP tool
// ({name, description, inputSchema}) or an OpenAI one ({type, function:{...}}).
func toolDefinition(text string) (indirect.Tool, string, bool) {
	var m map[string]any
	if json.Unmarshal([]byte(text), &m) != nil {
		return indirect.Tool{}, "", false
	}
	if fn, ok := m["function"].(map[string]any); ok {
		m = fn
	}
	desc, ok := m["description"].(string)
	if !ok {
		return indirect.Tool{}, "", false
	}
	name, _ := m["name"].(string)
	for _, key := range []string{"inputSchema", "parameters"} {
		if schema, present := m[key]; present {
			return indirect.Tool{Name: name, Description: desc, Schema: schema}, key, true
		}
	}
	if name == "" {
		return indirect.Tool{}, "", false
	}
	return indirect.Tool{Name: name, Description: desc}, "inputSchema", true
}

// RunIndirect sends every row through the gateway's untrusted-content path,
// as if it had arrived in a tool message rather than from the user: a row
// that is a tool definition is scored like tools[] (detector plus MCP
// signals, ScoreTool), any other row like a tool result (sanitizer, then the
// detector with the tool source hint). Benign rows measure the false
// positives of treating ordinary text as tool output.
func RunIndirect(ctx context.Context, rows []Row, runner *inference.Runner) ([]Result, error) {
	s := indirect.Scanner{Runner: runner}
	out := make([]Result, 0, len(rows))
	for _, row := range rows {
		start := time.Now()
		res := Result{Row: row}
		var score float64
		var err error
		if tool, key, ok := toolDefinition(row.Text); ok {
			var tv indirect.ToolVerdict
			tv, err = s.ScoreTool(ctx, tool, key, false)
			score = tv.Score
			if errors.Is(err, indirect.ErrSchemaTooDeep) {
				res.Rejected, res.Score, err = true, 1, nil
			}
		} else {
			cleaned, rep, serr := sanitizer.Sanitize(row.Text)
			if serr != nil {
				res.Rejected, res.Score = true, 1
			} else {
				res.Anomaly = float64(rep.AnomalyScore)
				var v indirect.Verdict
				v, err = s.Score(ctx, cleaned, indirect.SourceTool)
				score = v.Score
			}
		}
		switch {
		case res.Rejected:
		case errors.Is(err, inference.ErrInputTooLong):
			res.Rejected, res.Score = true, 1
		case err != nil:
			return nil, fmt.Errorf("row %s: %w", row.ID, err)
		default:
			res.Score = score
		}
		res.Latency = time.Since(start)
		out = append(out, res)
	}
	return out, nil
}
