package evalset

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
)

var updateBaseline = flag.Bool("update-baseline", false, "rewrite eval/baseline.json from the current detector")

const (
	dataDir      = "../../eval/data"
	baselinePath = "../../eval/baseline.json"
)

// TestBaseline scores the committed eval set with the regex detector and
// fails on a regression of more than 0.02 versus eval/baseline.json, the
// same check as `go run ./cmd/eval -baseline eval/baseline.json`.
// Refresh with: go test ./internal/evalset -run TestBaseline -update-baseline
func TestBaseline(t *testing.T) {
	rows, err := Load(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no .jsonl") {
			t.Skip("eval data not present")
		}
		t.Fatal(err)
	}
	det, err := Detectors["regex"]()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), rows, det)
	if err != nil {
		t.Fatal(err)
	}
	rep := BuildReport("regex", res)
	var sb strings.Builder
	rep.WriteTable(&sb)
	t.Log("\n" + sb.String())

	if *updateBaseline {
		b, err := MarshalReport(rep)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(baselinePath, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	var base Report
	if err := json.Unmarshal(b, &base); err != nil {
		t.Fatal(err)
	}
	if regs := Compare(base, rep, 0.02); len(regs) > 0 {
		t.Fatalf("regressions versus %s:\n  %s", baselinePath, strings.Join(regs, "\n  "))
	}
}
