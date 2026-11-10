package evalset

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSplitOf(t *testing.T) {
	for _, c := range []struct {
		row  Row
		want string
	}{
		{Row{ID: "en-7e7a0698f5f0"}, SplitDev},
		{Row{ID: "vi-7e7a0698f5f7"}, SplitDev},
		{Row{ID: "en-7e7a0698f5f8"}, SplitHoldout},
		{Row{ID: "en-7e7a0698f5ff"}, SplitHoldout},
		{Row{ID: "en-7e7a0698f5f8", Split: SplitDev}, SplitDev}, // the field wins
		{Row{ID: "a1"}, ""},
		{Row{ID: "en-7E7A0698F5F8"}, ""},
	} {
		if got := SplitOf(c.row); got != c.want {
			t.Errorf("SplitOf(%+v) = %q, want %q", c.row, got, c.want)
		}
	}
}

func TestSlices(t *testing.T) {
	res := func(id, label, lang, pos string, score float64) Result {
		return Result{Row: Row{ID: id, Label: label, Category: label, Lang: lang, Variant: "orig", Position: pos}, Score: score}
	}
	results := []Result{
		res("en-000000000000", "attack", "en", "comment", 0.9),
		res("en-000000000001", "attack", "en", "start", 0.1),
		res("en-000000000002", "benign", "en", "comment", 0.05),
		res("vi-00000000000f", "attack", "vi", "comment", 0.95),
		res("vi-00000000000e", "benign", "vi", "start", 0.9),
		res("xx", "attack", "en", "", 0.9), // no split: only in groups
	}
	rep := BuildReport("test", results)
	dev, hold := rep.Slices[SplitDev], rep.Slices[SplitHoldout]
	if dev.NPos != 2 || dev.NNeg != 1 || hold.NPos != 1 || hold.NNeg != 1 {
		t.Fatalf("dev %d/%d holdout %d/%d", dev.NPos, dev.NNeg, hold.NPos, hold.NNeg)
	}
	if *dev.At085.TPR != 0.5 || *dev.At085.FPR != 0 || *hold.At085.TPR != 1 || *hold.At085.FPR != 1 {
		t.Errorf("dev %+v holdout %+v", dev.At085, hold.At085)
	}
	if c := rep.Slices["position:comment"]; c.NPos != 2 || c.NNeg != 1 {
		t.Errorf("position:comment %d/%d", c.NPos, c.NNeg)
	}
	if _, ok := rep.Slices["en/dev"]; !ok {
		t.Error("no en/dev slice")
	}
	if rep.Groups["all"].NPos != 4 {
		t.Errorf("all n_attack %d, want 4", rep.Groups["all"].NPos)
	}
	var sb strings.Builder
	rep.WriteTable(&sb)
	if !strings.Contains(sb.String(), "holdout ") {
		t.Errorf("table has no holdout row:\n%s", sb.String())
	}

	// Slices are compared when the baseline has them.
	worse := BuildReport("test", append(results[:0:0], results...))
	worse.Slices = nil
	if regs := Compare(rep, worse, 0.02); len(regs) == 0 || !strings.Contains(regs[0], "slice") {
		t.Errorf("missing slices not reported: %v", regs)
	}
	if regs := Compare(worse, rep, 0.02); len(regs) != 0 {
		t.Errorf("baseline without slices: %v", regs)
	}
}

// TestNoSlicesWithoutSplit: rows whose ids carry no split keep the report as
// it was, without a "slices" key.
func TestNoSlicesWithoutSplit(t *testing.T) {
	rep := BuildReport("test", []Result{{Row: Row{ID: "a1", Label: "attack", Lang: "en"}, Score: 1}})
	b, err := MarshalReport(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"slices"`) {
		t.Errorf("slices in %s", b)
	}
}

// TestOldBaselinesCompatible: the committed baselines (no slices) still
// decode and compare clean against themselves.
func TestOldBaselinesCompatible(t *testing.T) {
	for _, p := range []string{"../../eval/baseline.json", "../../eval/codelog/baseline.json"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var rep Report
		if err := json.Unmarshal(b, &rep); err != nil {
			t.Fatal(err)
		}
		if regs := Compare(rep, rep, 0); len(regs) != 0 {
			t.Errorf("%s: %v", p, regs)
		}
	}
}
