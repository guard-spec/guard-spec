package evalset

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
)

// FPRBudget is the false-positive budget for the "TPR at FPR <= 1%" point.
const FPRBudget = 0.01

// Point is TPR/FPR at one threshold. Nil means the class was empty.
type Point struct {
	TPR *float64 `json:"tpr,omitempty"`
	FPR *float64 `json:"fpr,omitempty"`
}

// Metrics describes one group of rows.
type Metrics struct {
	NPos     int      `json:"n_attack"`
	NNeg     int      `json:"n_benign"`
	AUC      *float64 `json:"roc_auc,omitempty"`
	AtFPR1   Point    `json:"at_fpr_1pct"`
	At085    Point    `json:"at_0.85"`
	At060    Point    `json:"at_0.60"`
	Gateway  Point    `json:"gateway_rule"`
	Rejected int      `json:"rejected"`
}

// Latency summarises per-row pipeline latency.
type Latency struct {
	P50Micros float64 `json:"p50_us"`
	P95Micros float64 `json:"p95_us,omitempty"`
	P99Micros float64 `json:"p99_us"`
}

// Report is the runner output and the baseline format.
type Report struct {
	Detector string `json:"detector"`
	Rows     int    `json:"rows"`
	// ThresholdFPR1 is the global threshold where FPR on all benign rows is
	// <= FPRBudget; every group's at_fpr_1pct uses it. Nil means +/-Inf.
	ThresholdFPR1 *float64           `json:"threshold_fpr_1pct,omitempty"`
	Latency       map[string]Latency `json:"latency"`
	Groups        map[string]Metrics `json:"groups"`
}

func ptr(x float64) *float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return nil
	}
	r := math.Round(x*1e4) / 1e4
	return &r
}

type group struct {
	pos, neg []Result
}

// BuildReport groups results and computes every metric.
func BuildReport(detector string, results []Result) Report {
	groups := map[string]*group{}
	get := func(k string) *group {
		if groups[k] == nil {
			groups[k] = &group{}
		}
		return groups[k]
	}
	benignByLangVariant := map[string][]Result{}
	for _, r := range results {
		row := r.Row
		if row.IsAttack() {
			for _, k := range []string{"all", row.Lang, row.Lang + "/" + row.Category, row.Lang + "/variant:" + row.Variant} {
				get(k).pos = append(get(k).pos, r)
			}
			continue
		}
		for _, k := range []string{"all", row.Lang, row.Lang + "/benign"} {
			get(k).neg = append(get(k).neg, r)
		}
		benignByLangVariant[row.Lang+"/variant:"+row.Variant] = append(benignByLangVariant[row.Lang+"/variant:"+row.Variant], r)
	}
	// Category groups compare against all benign rows of the language. Variant
	// groups use benign rows of the same variant when there are any.
	for k, g := range groups {
		lang, rest, ok := strings.Cut(k, "/")
		if !ok || rest == "benign" {
			continue
		}
		if strings.HasPrefix(rest, "variant:") && len(benignByLangVariant[k]) > 0 {
			g.neg = benignByLangVariant[k]
		} else {
			g.neg = groups[lang].neg
		}
	}
	for k, neg := range benignByLangVariant {
		if groups[k] == nil {
			groups[k] = &group{neg: neg}
		}
	}

	thr := ThresholdAtFPR(scores(groups["all"].neg), FPRBudget)
	rep := Report{Detector: detector, Rows: len(results), ThresholdFPR1: ptr(thr),
		Latency: map[string]Latency{}, Groups: map[string]Metrics{}}
	for k, g := range groups {
		rep.Groups[k] = metricsFor(g, thr)
	}
	for _, k := range []string{"all", "en", "vi"} {
		var ds []time.Duration
		for _, r := range results {
			if k == "all" || r.Row.Lang == k {
				ds = append(ds, r.Latency)
			}
		}
		rep.Latency[k] = Latency{
			P50Micros: math.Round(float64(Percentile(ds, 50).Nanoseconds())/10) / 100,
			P95Micros: math.Round(float64(Percentile(ds, 95).Nanoseconds())/10) / 100,
			P99Micros: math.Round(float64(Percentile(ds, 99).Nanoseconds())/10) / 100,
		}
	}
	return rep
}

func scores(rs []Result) []float64 {
	out := make([]float64, len(rs))
	for i, r := range rs {
		out[i] = r.Score
	}
	return out
}

func gatewayRate(rs []Result) float64 {
	if len(rs) == 0 {
		return math.NaN()
	}
	n := 0
	for _, r := range rs {
		if r.GatewayBlocks() {
			n++
		}
	}
	return float64(n) / float64(len(rs))
}

func metricsFor(g *group, thrFPR1 float64) Metrics {
	pos, neg := scores(g.pos), scores(g.neg)
	m := Metrics{NPos: len(pos), NNeg: len(neg), AUC: ptr(ROCAUC(pos, neg))}
	point := func(t float64) Point {
		tpr, fpr := Rates(pos, neg, t)
		return Point{TPR: ptr(tpr), FPR: ptr(fpr)}
	}
	m.AtFPR1 = point(thrFPR1)
	m.At085 = point(InjectionBlockThreshold)
	m.At060 = point(0.6)
	m.Gateway = Point{TPR: ptr(gatewayRate(g.pos)), FPR: ptr(gatewayRate(g.neg))}
	for _, r := range append(append([]Result(nil), g.pos...), g.neg...) {
		if r.Rejected {
			m.Rejected++
		}
	}
	return m
}

// SortedGroups returns group names: all, en, vi, then the rest alphabetically.
func (r Report) SortedGroups() []string {
	rank := map[string]int{"all": 0, "en": 1, "vi": 2}
	keys := make([]string, 0, len(r.Groups))
	for k := range r.Groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri, okI := rank[keys[i]]
		rj, okJ := rank[keys[j]]
		switch {
		case okI && okJ:
			return ri < rj
		case okI != okJ:
			return okI
		}
		return keys[i] < keys[j]
	})
	return keys
}

func f(p *float64) string {
	if p == nil {
		return "    -"
	}
	return fmt.Sprintf("%5.3f", *p)
}

// WriteTable prints a human-readable summary.
func (r Report) WriteTable(w io.Writer) {
	thr := "none"
	if r.ThresholdFPR1 != nil {
		thr = fmt.Sprintf("%.4f", *r.ThresholdFPR1)
	}
	fmt.Fprintf(w, "detector=%s rows=%d threshold@FPR<=1%%=%s\n", r.Detector, r.Rows, thr)
	fmt.Fprintf(w, "%-28s %5s %5s  %5s | %-11s | %-11s | %-11s | %-11s\n",
		"group", "n_att", "n_ben", "AUC", "TPR/FPR@1%", "TPR/FPR@.85", "TPR/FPR@.60", "gateway")
	for _, k := range r.SortedGroups() {
		m := r.Groups[k]
		fmt.Fprintf(w, "%-28s %5d %5d  %s | %s %s | %s %s | %s %s | %s %s\n", k, m.NPos, m.NNeg, f(m.AUC),
			f(m.AtFPR1.TPR), f(m.AtFPR1.FPR), f(m.At085.TPR), f(m.At085.FPR),
			f(m.At060.TPR), f(m.At060.FPR), f(m.Gateway.TPR), f(m.Gateway.FPR))
	}
	for _, k := range []string{"all", "en", "vi"} {
		l := r.Latency[k]
		fmt.Fprintf(w, "latency %-3s p50=%.1fus p95=%.1fus p99=%.1fus\n", k, l.P50Micros, l.P95Micros, l.P99Micros)
	}
}

// MarshalReport encodes a report in the committed baseline format.
func MarshalReport(r Report) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Compare lists metrics in cur that are worse than base by more than maxDrop.
// TPR and AUC must not fall; FPR must not rise. Latency is not compared
// because it depends on the machine.
func Compare(base, cur Report, maxDrop float64) []string {
	var out []string
	if base.Rows != cur.Rows {
		out = append(out, fmt.Sprintf("dataset changed: baseline has %d rows, current %d; regenerate the baseline", base.Rows, cur.Rows))
	}
	for _, k := range base.SortedGroups() {
		b := base.Groups[k]
		c, ok := cur.Groups[k]
		if !ok {
			out = append(out, fmt.Sprintf("%s: group missing", k))
			continue
		}
		higher := func(name string, bv, cv *float64) {
			if bv != nil && (cv == nil || *bv-*cv > maxDrop+1e-9) {
				out = append(out, fmt.Sprintf("%s: %s fell %s -> %s", k, name, f(bv), f(cv)))
			}
		}
		lower := func(name string, bv, cv *float64) {
			if bv != nil && (cv == nil || *cv-*bv > maxDrop+1e-9) {
				out = append(out, fmt.Sprintf("%s: %s rose %s -> %s", k, name, f(bv), f(cv)))
			}
		}
		higher("roc_auc", b.AUC, c.AUC)
		higher("tpr@fpr1%", b.AtFPR1.TPR, c.AtFPR1.TPR)
		lower("fpr@fpr1%", b.AtFPR1.FPR, c.AtFPR1.FPR)
		higher("tpr@0.85", b.At085.TPR, c.At085.TPR)
		lower("fpr@0.85", b.At085.FPR, c.At085.FPR)
		higher("tpr@0.60", b.At060.TPR, c.At060.TPR)
		lower("fpr@0.60", b.At060.FPR, c.At060.FPR)
		higher("gateway tpr", b.Gateway.TPR, c.Gateway.TPR)
		lower("gateway fpr", b.Gateway.FPR, c.Gateway.FPR)
	}
	return out
}
