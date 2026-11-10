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

func TestToolPathFlags(t *testing.T) {
	for _, tt := range []struct {
		noCorr, capped bool
		want           string
	}{{false, false, "/tool"}, {true, false, "/tool/no-corroboration"}, {false, true, "/tool/l2cap"}, {true, true, "/tool/no-corroboration/l2cap"}} {
		if got := toolPathName(tt.noCorr, tt.capped); got != tt.want {
			t.Errorf("toolPathName(%v, %v) = %q, want %q", tt.noCorr, tt.capped, got, tt.want)
		}
	}
	for _, tt := range []struct {
		flag, env string
		off       bool
		bad       bool
	}{{"", "", false, false}, {"on", "", false, false}, {"off", "", true, false}, {"", "off", true, false}, {"on", "off", false, false}, {"maybe", "", false, true}} {
		off, err := parseCorroboration(tt.flag, tt.env)
		if (err != nil) != tt.bad || off != tt.off {
			t.Errorf("parseCorroboration(%q, %q) = %v, %v", tt.flag, tt.env, off, err)
		}
	}
	for _, tt := range []struct {
		v   string
		on  bool
		bad bool
	}{{"", true, false}, {"on", true, false}, {"OFF", false, false}, {"2", false, true}} {
		on, err := parseOnOff("-l2cap", tt.v)
		if (err != nil) != tt.bad || on != tt.on {
			t.Errorf("parseOnOff(%q) = %v, %v", tt.v, on, err)
		}
	}
	if code := runWith(t, "-data", "../../eval/data", "-path", "tool", "-l2cap", "maybe"); code != 2 {
		t.Fatalf("bad -l2cap: exit code %d, want 2", code)
	}
	if code := runWith(t, "-data", "../../eval/data", "-corroboration", "off"); code != 2 {
		t.Fatalf("-corroboration off on the direct path: exit code %d, want 2", code)
	}
}
