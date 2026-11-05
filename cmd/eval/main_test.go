package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/guard-spec/guard-spec/internal/evalset"
)

func runWith(t *testing.T, args ...string) int {
	t.Helper()
	oldArgs, oldFlags := os.Args, flag.CommandLine
	defer func() { os.Args, flag.CommandLine = oldArgs, oldFlags }()
	flag.CommandLine = flag.NewFlagSet("eval", flag.ContinueOnError)
	os.Args = append([]string{"eval"}, args...)
	return run()
}

// TestCLIAgainstBaseline runs the same invocation as CI.
func TestCLIAgainstBaseline(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	code := runWith(t, "-data", "../../eval/data", "-baseline", "../../eval/baseline.json", "-json", out)
	if code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep evalset.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Rows == 0 || rep.Groups["all"].NPos == 0 {
		t.Fatalf("empty report: %+v", rep)
	}
}

// TestCLIRegressionExitCode checks that a better baseline makes the run fail.
func TestCLIRegressionExitCode(t *testing.T) {
	b, err := os.ReadFile("../../eval/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var base evalset.Report
	if err := json.Unmarshal(b, &base); err != nil {
		t.Fatal(err)
	}
	m := base.Groups["all"]
	better := *m.At085.TPR + 0.05
	m.At085.TPR = &better
	base.Groups["all"] = m
	path := filepath.Join(t.TempDir(), "baseline.json")
	nb, _ := evalset.MarshalReport(base)
	if err := os.WriteFile(path, nb, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runWith(t, "-data", "../../eval/data", "-baseline", path, "-max-regression", "0.02"); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if code := runWith(t, "-data", "../../eval/data", "-detector", "nope"); code != 2 {
		t.Fatalf("unknown detector exit code %d, want 2", code)
	}
}

// TestMLDetectorNeedsModels: fusion-ml refuses to run on L1 alone, so a
// baseline for the model layers is never compared with L1 numbers.
func TestMLDetectorNeedsModels(t *testing.T) {
	t.Setenv("MODEL_DIR", t.TempDir())
	if code := runWith(t, "-data", "../../eval/data", "-detector", "fusion-ml"); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
	if code := runWith(t, "-data", "../../eval/data", "-layers", "l9"); code != 2 {
		t.Fatalf("bad -layers: exit code %d, want 2", code)
	}
}
