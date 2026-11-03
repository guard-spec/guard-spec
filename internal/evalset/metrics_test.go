package evalset

import (
	"math"
	"testing"
	"time"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestROCAUC(t *testing.T) {
	cases := []struct {
		name     string
		pos, neg []float64
		want     float64
	}{
		{"perfect", []float64{0.9, 0.8}, []float64{0.1, 0.2}, 1},
		{"inverted", []float64{0.1}, []float64{0.9, 0.8}, 0},
		{"all tied", []float64{0.5, 0.5}, []float64{0.5, 0.5, 0.5}, 0.5},
		// pairs: (0.9>0.5) (0.9>0.1) (0.5=0.5 ->0.5) (0.5>0.1) (0.1<0.5) (0.1=0.1 ->0.5) = 4/6
		{"mixed ties", []float64{0.9, 0.5, 0.1}, []float64{0.5, 0.1}, 4.0 / 6},
		{"one of three", []float64{0.4}, []float64{0.3, 0.5, 0.6}, 1.0 / 3},
	}
	for _, c := range cases {
		if got := ROCAUC(c.pos, c.neg); !near(got, c.want) {
			t.Errorf("%s: ROCAUC = %v, want %v", c.name, got, c.want)
		}
	}
	if !math.IsNaN(ROCAUC(nil, []float64{1})) || !math.IsNaN(ROCAUC([]float64{1}, nil)) {
		t.Error("ROCAUC with an empty class should be NaN")
	}
}

// bruteAUC counts pairs directly, to cross-check the rank formula.
func bruteAUC(pos, neg []float64) float64 {
	var s float64
	for _, p := range pos {
		for _, n := range neg {
			switch {
			case p > n:
				s++
			case p == n:
				s += 0.5
			}
		}
	}
	return s / float64(len(pos)*len(neg))
}

func TestROCAUCMatchesPairCount(t *testing.T) {
	levels := []float64{0.02, 0.72, 0.85, 0.88, 0.92, 0.97}
	var pos, neg []float64
	for i := 0; i < 50; i++ {
		pos = append(pos, levels[(i*7+3)%len(levels)])
		neg = append(neg, levels[(i*i)%3])
	}
	if got, want := ROCAUC(pos, neg), bruteAUC(pos, neg); !near(got, want) {
		t.Fatalf("ROCAUC = %v, brute force = %v", got, want)
	}
}

func TestRates(t *testing.T) {
	tpr, fpr := Rates([]float64{0.9, 0.85, 0.5, 0.1}, []float64{0.86, 0.2}, 0.85)
	if !near(tpr, 0.5) || !near(fpr, 0.5) {
		t.Fatalf("Rates = %v, %v; want 0.5, 0.5 (threshold is inclusive)", tpr, fpr)
	}
}

func TestTPRAtFPR(t *testing.T) {
	// 100 negatives: 98 at 0.02, one at 0.72, one at 0.9.
	neg := make([]float64, 0, 100)
	for i := 0; i < 98; i++ {
		neg = append(neg, 0.02)
	}
	neg = append(neg, 0.72, 0.9)
	pos := []float64{0.95, 0.9, 0.8, 0.72, 0.5, 0.02}

	// 1% of 100 allows one false positive: flag only the 0.9 negative, so the
	// threshold sits just above 0.72 and catches every positive above it.
	tpr, fpr, thr := TPRAtFPR(pos, neg, 0.01)
	if !(thr > 0.72 && thr <= 0.8) {
		t.Fatalf("threshold = %v, want in (0.72, 0.8]", thr)
	}
	if !near(fpr, 0.01) || !near(tpr, 3.0/6) {
		t.Fatalf("TPR/FPR = %v/%v, want 0.5/0.01", tpr, fpr)
	}

	// 2% allows both outliers: threshold just above 0.02.
	tpr, fpr, thr = TPRAtFPR(pos, neg, 0.02)
	if !(thr > 0.02 && thr < 0.5) || !near(fpr, 0.02) || !near(tpr, 5.0/6) {
		t.Fatalf("2%%: thr=%v tpr=%v fpr=%v", thr, tpr, fpr)
	}

	// Zero budget: nothing negative may be flagged.
	tpr, fpr, thr = TPRAtFPR(pos, neg, 0)
	if !(thr > 0.9) || fpr != 0 || !near(tpr, 1.0/6) {
		t.Fatalf("0%%: thr=%v tpr=%v fpr=%v", thr, tpr, fpr)
	}

	// Budget never exceeded even when ties straddle it: 3 negatives at 0.9
	// out of 100 cannot be split, so 1% must exclude all of them.
	tied := append(make([]float64, 97), 0.9, 0.9, 0.9)
	if _, fpr, _ := TPRAtFPR(pos, tied, 0.01); fpr > 0.01 {
		t.Fatalf("FPR %v exceeds the budget", fpr)
	}

	// Full budget flags everything.
	if thr := ThresholdAtFPR(neg, 1); !math.IsInf(thr, -1) {
		t.Fatalf("budget 1: threshold = %v, want -Inf", thr)
	}
	if thr := ThresholdAtFPR(nil, 0.01); !math.IsInf(thr, 1) {
		t.Fatalf("no negatives: threshold = %v, want +Inf", thr)
	}
}

func TestPercentile(t *testing.T) {
	ds := []time.Duration{5, 1, 4, 2, 3, 6, 7, 8, 9, 10}
	if got := Percentile(ds, 50); got != 5 {
		t.Errorf("p50 = %v, want 5", got)
	}
	if got := Percentile(ds, 99); got != 10 {
		t.Errorf("p99 = %v, want 10", got)
	}
	if Percentile(nil, 50) != 0 {
		t.Error("empty percentile should be 0")
	}
}

func TestCompare(t *testing.T) {
	v := func(x float64) *float64 { return &x }
	base := Report{Rows: 10, Groups: map[string]Metrics{"all": {
		AUC: v(0.9), AtFPR1: Point{TPR: v(0.5), FPR: v(0.01)}, At085: Point{TPR: v(0.6), FPR: v(0.02)},
	}}}
	ok := Report{Rows: 10, Groups: map[string]Metrics{"all": {
		AUC: v(0.885), AtFPR1: Point{TPR: v(0.49), FPR: v(0.01)}, At085: Point{TPR: v(0.6), FPR: v(0.035)},
	}}}
	if regs := Compare(base, ok, 0.02); len(regs) != 0 {
		t.Fatalf("within tolerance, got %v", regs)
	}
	bad := Report{Rows: 10, Groups: map[string]Metrics{"all": {
		AUC: v(0.85), AtFPR1: Point{TPR: v(0.5), FPR: v(0.01)}, At085: Point{TPR: v(0.6), FPR: v(0.05)},
	}}}
	if regs := Compare(base, bad, 0.02); len(regs) != 2 {
		t.Fatalf("want AUC drop and FPR rise, got %v", regs)
	}
	if regs := Compare(base, Report{Rows: 10, Groups: map[string]Metrics{}}, 0.02); len(regs) != 1 {
		t.Fatalf("missing group should be reported, got %v", regs)
	}
}
