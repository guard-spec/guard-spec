package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guard-spec/guard-spec/internal/evalset"
)

// TestCLIScores: -scores writes one line per row, in input order, with the
// gateway decision (bench/ reads it).
func TestCLIScores(t *testing.T) {
	out := filepath.Join(t.TempDir(), "scores.jsonl")
	if code := runWith(t, "-data", "../../eval/data", "-scores", out); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	rows, err := evalset.Load("../../eval/data")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != len(rows) {
		t.Fatalf("%d score lines, want %d", len(lines), len(rows))
	}
	blocked := 0
	for i, line := range lines {
		var s evalset.RowScore
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if s.ID != rows[i].ID || s.Label != rows[i].Label || s.Lang != rows[i].Lang {
			t.Fatalf("line %d: %+v does not match row %s", i+1, s, rows[i].ID)
		}
		if s.Score < 0 || s.Score > 1 || s.LatencyUS <= 0 {
			t.Fatalf("line %d: bad score or latency: %+v", i+1, s)
		}
		if s.Blocked {
			blocked++
		}
	}
	if blocked == 0 || blocked == len(lines) {
		t.Fatalf("blocked %d of %d rows", blocked, len(lines))
	}
}

// TestCLIScoresBadPath: an unwritable -scores path is a usage error.
func TestCLIScoresBadPath(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "missing", "scores.jsonl")
	if code := runWith(t, "-data", "../../eval/data", "-scores", bad); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
}
