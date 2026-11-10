package evalset

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Dev/holdout splits (eval/README.md): a row whose id ends in 0-7 is dev, 8-f
// holdout. Rules and models may be tuned by reading dev rows only.
const (
	SplitDev     = "dev"
	SplitHoldout = "holdout"
)

var hexID = regexp.MustCompile(`^[a-z]{2}-[0-9a-f]{12}$`)

// SplitOf returns the row's split: its "split" field when set (eval/embedded
// takes it from the payload), else the last hex digit of a "<lang>-<12 hex>"
// id, else "".
func SplitOf(r Row) string {
	if r.Split != "" {
		return r.Split
	}
	if !hexID.MatchString(r.ID) {
		return ""
	}
	if c := r.ID[len(r.ID)-1]; c >= '0' && c <= '7' {
		return SplitDev
	}
	return SplitHoldout
}

// SliceMetrics is a Metrics whose at_fpr_1pct uses the slice's own threshold
// (FPR <= 1% on the slice's benign rows), so dev and holdout each report
// TPR at FPR <= 1% on their own negatives.
type SliceMetrics struct {
	Metrics
	ThresholdFPR1 *float64 `json:"threshold_fpr_1pct,omitempty"`
}

// buildSlices computes the dev/holdout slices: "dev", "holdout", per
// language ("en/dev"), and per embedding position when rows carry one
// ("position:comment", both splits: per position and split the groups are
// too small to compare). Attacks and benign rows go
// to the slice they match, so a slice's FPR uses benign rows of the same
// split (and position). It returns nil when no row has a split.
func buildSlices(results []Result) map[string]SliceMetrics {
	groups := map[string]*group{}
	add := func(k string, r Result) {
		if groups[k] == nil {
			groups[k] = &group{}
		}
		if r.Row.IsAttack() {
			groups[k].pos = append(groups[k].pos, r)
		} else {
			groups[k].neg = append(groups[k].neg, r)
		}
	}
	for _, r := range results {
		split := SplitOf(r.Row)
		if split == "" {
			continue
		}
		add(split, r)
		add(r.Row.Lang+"/"+split, r)
		if p := r.Row.Position; p != "" {
			add("position:"+p, r)
		}
	}
	if len(groups) == 0 {
		return nil
	}
	out := make(map[string]SliceMetrics, len(groups))
	for k, g := range groups {
		thr := ThresholdAtFPR(scores(g.neg), FPRBudget)
		out[k] = SliceMetrics{Metrics: metricsFor(g, thr), ThresholdFPR1: ptr(thr)}
	}
	return out
}

func (r Report) sortedSlices() []string {
	keys := make([]string, 0, len(r.Slices))
	for k := range r.Slices {
		keys = append(keys, k)
	}
	rank := func(k string) int {
		switch k {
		case SplitDev:
			return 0
		case SplitHoldout:
			return 1
		}
		if strings.HasPrefix(k, "position:") {
			return 3
		}
		return 2
	}
	sort.Slice(keys, func(i, j int) bool {
		if ri, rj := rank(keys[i]), rank(keys[j]); ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	return keys
}

func (r Report) writeSlices(w io.Writer) {
	if len(r.Slices) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "dev/holdout slices (at_fpr_1pct at each slice's own threshold):\n")
	for _, k := range r.sortedSlices() {
		m := r.Slices[k]
		_, _ = fmt.Fprintf(w, "%-28s %5d %5d  %s | %s %s | %s %s | %s %s | %s %s  thr=%s\n", k, m.NPos, m.NNeg, f(m.AUC),
			f(m.AtFPR1.TPR), f(m.AtFPR1.FPR), f(m.At085.TPR), f(m.At085.FPR),
			f(m.At060.TPR), f(m.At060.FPR), f(m.Gateway.TPR), f(m.Gateway.FPR), f(m.ThresholdFPR1))
	}
}
