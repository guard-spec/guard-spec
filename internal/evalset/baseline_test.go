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

var updateBaseline = flag.Bool("update-baseline", false, "rewrite the baseline files from the current detectors")

const dataDir = "../../eval/data"

// baselines maps each tracked detector to its committed baseline.
// eval/baseline.json belongs to the production detector (DefaultDetector),
// so `go run ./cmd/eval -baseline eval/baseline.json` checks what ships.
var baselines = map[string]string{
	DefaultDetector: "../../eval/baseline.json",
	"regex":         "../../eval/baseline-regex.json",
}

// TestBaseline scores the committed eval set with each tracked detector and
// fails on a regression of more than 0.02 versus its baseline, the same
// check as `go run ./cmd/eval -detector <name> -baseline <file>`.
// Refresh all:  go test ./internal/evalset -run TestBaseline -update-baseline
// Refresh one:  go test ./internal/evalset -run TestBaseline/fusion -update-baseline
func TestBaseline(t *testing.T) {
	rows, err := Load(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no .jsonl") {
			t.Skip("eval data not present")
		}
		t.Fatal(err)
	}
	for name, path := range baselines {
		t.Run(name, func(t *testing.T) {
			det, err := Detectors[name]()
			if err != nil {
				t.Fatal(err)
			}
			res, err := Run(context.Background(), rows, det)
			if err != nil {
				t.Fatal(err)
			}
			rep := BuildReport(name, res)
			var sb strings.Builder
			rep.WriteTable(&sb)
			t.Log("\n" + sb.String())

			if *updateBaseline {
				b, err := MarshalReport(rep)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var base Report
			if err := json.Unmarshal(b, &base); err != nil {
				t.Fatal(err)
			}
			if base.Detector != name {
				t.Fatalf("%s holds a baseline for %q, not %q", path, base.Detector, name)
			}
			if regs := Compare(base, rep, 0.02); len(regs) > 0 {
				t.Fatalf("regressions versus %s:\n  %s", path, strings.Join(regs, "\n  "))
			}
		})
	}
}
