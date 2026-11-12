package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/guard-spec/guard-spec/internal/evalset"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/inference/rules"
	"github.com/guard-spec/guard-spec/internal/sanitizer"
)

// scoredRow is one validation row with its raw layer scores.
type scoredRow struct {
	ID     string     `json:"id"`
	Lang   string     `json:"lang"`
	Attack bool       `json:"attack"`
	Raw    [3]float64 `json:"raw"` // L1, L2, L3 before calibration
	// L1Rules is how many rules fired (0: L1's score is cue words only).
	// Absent from caches written before it existed, which then read as 0.
	L1Rules int `json:"l1_rules,omitempty"`
}

// method turns calibrated layer scores into a fused score.
type method struct {
	name   string
	layers [3]bool
	logreg bool
}

var methods = []method{
	{name: "L1", layers: [3]bool{true, false, false}},
	{name: "L2", layers: [3]bool{false, true, false}},
	{name: "L3", layers: [3]bool{false, false, true}},
	{name: "max(L1,L2)", layers: [3]bool{true, true, false}},
	{name: "max(L1,L2,L3)", layers: [3]bool{true, true, true}},
	{name: "logreg(L1,L2)", layers: [3]bool{true, true, false}, logreg: true},
	{name: "logreg(L1,L2,L3)", layers: [3]bool{true, true, true}, logreg: true},
}

const ridge = 0.01

func runFit(args []string) int {
	fs := flag.NewFlagSet("fit", flag.ContinueOnError)
	val := fs.String("val", "train/data/val.jsonl,train/data/val_hard.jsonl,train/data/val_vi_variants.jsonl,train/data/val_v3.jsonl",
		"calibration split, comma-separated files (the classifier's validation splits; never eval/)")
	modelDir := fs.String("model-dir", "models", "MODEL_DIR")
	l2Dir := fs.String("l2", "", "L2_MODEL_DIR (default: MODEL_DIR/local/guardspec-classifier-v3b, then -v2, -v1, -v0)")
	l3Dir := fs.String("l3", "", "L3_MODEL_DIR (default: MODEL_DIR/cache/multilingual-e5-small)")
	folds := fs.Int("folds", 5, "cross-validation folds")
	write := fs.Bool("write", false, "write calibration.json into the classifier directory")
	fp16 := fs.Bool("fp16", false, "-write: store the fit as the \"fp16\" block of the existing calibration.json "+
		"(-l2 holds model_fp16.onnx and the INT8 model's calibration.json; INFERENCE_PROVIDER=cuda, or the FP16 file named model.onnx on the CPU)")
	cache := fs.String("cache", "", "read/write raw scores here (skips the models when the file exists)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx := context.Background()

	var rows []scoredRow
	var stack *ml.Stack
	if *cache != "" {
		if data, err := os.ReadFile(*cache); err == nil {
			if err := json.Unmarshal(data, &rows); err != nil {
				fmt.Fprintln(os.Stderr, "cache:", err)
				return 2
			}
			fmt.Printf("raw scores from %s (%d rows)\n", *cache, len(rows))
		}
	}
	if rows == nil || *write {
		var err error
		stack, err = ml.Build(ctx, ml.Config{ModelDir: *modelDir, L2Dir: *l2Dir, L3Dir: *l3Dir,
			Layers: [3]bool{true, true, true}, Fusion: "max"}, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		defer func() { _ = stack.Close() }()
		if stack.Degraded() {
			fmt.Fprintln(os.Stderr, "models missing:\n  "+strings.Join(stack.Problems, "\n  "))
			return 2
		}
		fmt.Printf("L2 %s (%s)\n", stack.L2Model, stack.L2Dir)
	}
	if rows == nil {
		var err error
		if rows, err = scoreSplit(ctx, *val, stack); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if *cache != "" {
			data, _ := json.Marshal(rows)
			if err := os.WriteFile(*cache, data, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "cache:", err)
				return 2
			}
		}
	}

	report(rows, *folds)

	// Final calibration on the whole split.
	l2 := fitLayer(rows, nil, fusion.L2)
	l3 := fitLayer(rows, nil, fusion.L3)
	fmt.Printf("\nPlatt on all %d rows of %s:\n", len(rows), *val)
	fmt.Printf("  L2: fusion.Calibration{A: %.4f, B: %.4f}\n", l2.A, l2.B)
	fmt.Printf("  L3: fusion.Calibration{A: %.4f, B: %.4f}\n", l3.A, l3.B)
	if d := ml.DefaultL3Calibration; math.Abs(l3.A-d.A) > 1e-3 || math.Abs(l3.B-d.B) > 1e-3 {
		fmt.Printf("  (L3 differs from ml.DefaultL3Calibration %+v. The L3 scaling is shared by every classifier,\n"+
			"   so the logistic regressions below use ml.DefaultL3Calibration, which is what runs.)\n", d)
	}
	// The combiners must be fitted on the layer scores the gateway computes:
	// L1 and L3 with their built-in calibrations, L2 with the one fitted here.
	cal := [3]fusion.Calibration{fusion.DefaultL1Calibration, l2, ml.DefaultL3Calibration}
	lrs := map[string]fusion.LogReg{}
	for _, m := range methods {
		if !m.logreg {
			continue
		}
		lr := fusion.FitLogReg(calibrated(rows, nil, cal), labels(rows, nil), m.layers, ridge)
		lrs[ml.LayerKey(m.layers)] = lr
		fmt.Printf("  %s: fusion.LogReg{W: [3]float64{%.4f, %.4f, %.4f}, B: %.4f}\n", m.name, lr.W[0], lr.W[1], lr.W[2], lr.B)
	}

	silent := l1Silent(rows)
	capL2 := untrustedMax(lrs, silent)
	fmt.Printf("  l2_untrusted_max: %.2f (L2 alone with L1 silent at raw %.3f and L3 neutral stays below %.2f on both paths)\n",
		capL2, silent, evalset.InjectionBlockThreshold)

	if *write {
		f := ml.CalibrationFile{Model: stack.L2Model, Platt: l2, LogReg: lrs, L2UntrustedMax: capL2,
			FittedOn: fmt.Sprintf("%s (%d rows), %s", *val, len(rows), time.Now().UTC().Format("2006-01-02"))}
		path := filepath.Join(stack.L2Dir, "calibration.json")
		if *fp16 {
			// The FP16 model's block inside the INT8 model's calibration.json.
			base, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintln(os.Stderr, "-fp16 needs the INT8 calibration.json first:", err)
				return 2
			}
			var top ml.CalibrationFile
			if err := json.Unmarshal(base, &top); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			f.Model, top.FP16 = "", &f
			f = top
		}
		data, _ := json.MarshalIndent(f, "", "  ")
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Println("wrote", path)
	}
	return 0
}

// l1Silent is the raw L1 score of a text where no rule fired, taken high: the
// 90th percentile over the benign rows without a rule (cue words alone give
// L1 a small score; on the validation splits the largest is about 0.17). A
// cache written before L1Rules existed reads every row as rule-free, so its
// benign rows with a rule count too: a higher level, hence a lower cap.
func l1Silent(rows []scoredRow) float64 {
	var xs []float64
	for _, r := range rows {
		if !r.Attack && r.L1Rules == 0 && r.Raw[fusion.L1] > 0 {
			xs = append(xs, r.Raw[fusion.L1])
		}
	}
	if len(xs) == 0 {
		return 0
	}
	sort.Float64s(xs)
	return xs[min(len(xs)-1, int(0.9*float64(len(xs))))]
}

// untrustedMax derives CalibrationFile.L2UntrustedMax: the largest calibrated
// L2 score, on a 0.01 grid, at which L2 alone cannot block untrusted content
// on either path, less one step of margin. "Alone" is L1 at its silent level
// (l1Silent, calibrated) and L3 at the neutral raw score 0.5 (calibrated),
// fused with each combiner in lrs (l1,l2,l3 on the short path; l1,l2 on the
// long path, where L3 does not run); "block" is evalset.InjectionBlockThreshold.
// The cap is a design rule rather than a fit: a classifier trained on attack
// payloads in code and log hosts is as certain about benign prose in such
// hosts, which the validation splits do not contain (RF-437128e9), so above
// the cap L1 or L3 must add the lift. 0 when no combiner is given.
func untrustedMax(lrs map[string]fusion.LogReg, l1Silent float64) float64 {
	if len(lrs) == 0 {
		return 0
	}
	p1 := fusion.DefaultL1Calibration.Apply(l1Silent)
	p3 := ml.DefaultL3Calibration.Apply(0.5)
	best := 1.0
	for key, lr := range lrs {
		layers := [3]float64{p1, 0, p3}
		if !strings.Contains(key, "l3") {
			layers[fusion.L3] = fusion.Missing
		}
		largest := 0.0
		for i := 1; i < 100; i++ {
			p2 := float64(i) / 100
			layers[fusion.L2] = p2
			s, ok := lr.Apply(layers)
			if !ok || s >= evalset.InjectionBlockThreshold {
				break
			}
			largest = p2
		}
		best = math.Min(best, largest)
	}
	return math.Round((best-0.01)*100) / 100
}

func scoreSplit(ctx context.Context, path string, stack *ml.Stack) ([]scoredRow, error) {
	var in []trainRow
	for _, p := range strings.Split(path, ",") {
		rows, err := readTrain(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		in = append(in, rows...)
	}
	l1 := fusion.RulesLayer{E: rules.New()}
	layers := [3]fusion.Layer{l1, stack.L2, stack.L3}
	var out []scoredRow
	start := time.Now()
	for i, r := range in {
		cleaned, _, err := sanitizer.Sanitize(r.Text)
		if err != nil {
			continue // the gateway rejects these before any layer
		}
		row := scoredRow{ID: r.ID, Lang: r.Lang, Attack: r.attack()}
		for slot, l := range layers {
			res, err := l.Score(ctx, cleaned)
			if err != nil {
				return nil, fmt.Errorf("row %s layer %d: %w", r.ID, slot+1, err)
			}
			row.Raw[slot] = res.Score
			if slot == fusion.L1 {
				row.L1Rules = len(res.Rules)
			}
		}
		out = append(out, row)
		if (i+1)%500 == 0 {
			fmt.Fprintf(os.Stderr, "scored %d/%d (%s)\n", i+1, len(in), time.Since(start).Round(time.Second))
		}
	}
	return out, nil
}

// fitLayer fits Platt for one layer on the rows where keep is true (nil: all).
func fitLayer(rows []scoredRow, keep func(int) bool, slot int) fusion.Calibration {
	var s []float64
	var y []bool
	for i, r := range rows {
		if keep == nil || keep(i) {
			s = append(s, r.Raw[slot])
			y = append(y, r.Attack)
		}
	}
	return fusion.FitPlatt(s, y)
}

func calibrated(rows []scoredRow, keep func(int) bool, cal [3]fusion.Calibration) [][3]float64 {
	var out [][3]float64
	for i, r := range rows {
		if keep == nil || keep(i) {
			var p [3]float64
			for k := range p {
				p[k] = cal[k].Apply(r.Raw[k])
			}
			out = append(out, p)
		}
	}
	return out
}

func labels(rows []scoredRow, keep func(int) bool) []bool {
	var out []bool
	for i, r := range rows {
		if keep == nil || keep(i) {
			out = append(out, r.Attack)
		}
	}
	return out
}

func foldOf(id string, k int) int {
	h := fnv.New32a()
	h.Write([]byte(id))
	return int(h.Sum32() % uint32(k))
}

// crossValidate returns out-of-fold fused scores per method.
func crossValidate(rows []scoredRow, k int) map[string][]float64 {
	pred := map[string][]float64{}
	for _, m := range methods {
		pred[m.name] = make([]float64, len(rows))
	}
	for f := 0; f < k; f++ {
		train := func(i int) bool { return foldOf(rows[i].ID, k) != f }
		cal := [3]fusion.Calibration{fusion.DefaultL1Calibration, fitLayer(rows, train, fusion.L2), fitLayer(rows, train, fusion.L3)}
		ptrain, ytrain := calibrated(rows, train, cal), labels(rows, train)
		for _, m := range methods {
			var lr fusion.LogReg
			if m.logreg {
				lr = fusion.FitLogReg(ptrain, ytrain, m.layers, ridge)
			}
			for i, r := range rows {
				if train(i) {
					continue
				}
				var p [3]float64
				for s := range p {
					p[s] = cal[s].Apply(r.Raw[s])
				}
				if m.logreg {
					pred[m.name][i], _ = lr.Apply(p)
					continue
				}
				best := 0.0
				for s, on := range m.layers {
					if on {
						best = math.Max(best, p[s])
					}
				}
				pred[m.name][i] = best
			}
		}
	}
	return pred
}

func report(rows []scoredRow, folds int) {
	var nA, nB, zeroA, zeroB int
	for _, r := range rows {
		if r.Attack {
			nA++
			if r.Raw[fusion.L1] == 0 {
				zeroA++
			}
		} else {
			nB++
			if r.Raw[fusion.L1] == 0 {
				zeroB++
			}
		}
	}
	fmt.Printf("\n%d rows (%d attack, %d benign). No L1 rule fired: %d attacks (%.1f%%), %d benign (%.1f%%)\n",
		len(rows), nA, nB, zeroA, 100*float64(zeroA)/float64(nA), zeroB, 100*float64(zeroB)/float64(nB))

	pred := crossValidate(rows, folds)
	fmt.Printf("\nOut-of-fold metrics (%d-fold CV on the calibration split):\n", folds)
	fmt.Printf("%-18s %8s %8s %7s %7s %7s %13s %13s\n", "method", "logloss", "brier", "AUC", "AUC-en", "AUC-vi", "TPR@FPR<=1%", "TPR/FPR@0.85")
	for _, m := range methods {
		name := m.name
		p := pred[name]
		var ll, br float64
		var pos, neg []float64
		lang := map[string][2][]float64{}
		for i, r := range rows {
			q := math.Min(math.Max(p[i], 1e-6), 1-1e-6)
			y := 0.0
			if r.Attack {
				y = 1
				pos = append(pos, p[i])
			} else {
				neg = append(neg, p[i])
			}
			ll -= y*math.Log(q) + (1-y)*math.Log(1-q)
			br += (p[i] - y) * (p[i] - y)
			l := lang[r.Lang]
			if r.Attack {
				l[0] = append(l[0], p[i])
			} else {
				l[1] = append(l[1], p[i])
			}
			lang[r.Lang] = l
		}
		n := float64(len(rows))
		tpr1, _, _ := evalset.TPRAtFPR(pos, neg, evalset.FPRBudget)
		t85, f85 := evalset.Rates(pos, neg, 0.85)
		fmt.Printf("%-18s %8.4f %8.4f %7.4f %7.4f %7.4f %13.4f %6.4f/%.4f\n", name, ll/n, br/n,
			evalset.ROCAUC(pos, neg), evalset.ROCAUC(lang["en"][0], lang["en"][1]), evalset.ROCAUC(lang["vi"][0], lang["vi"][1]),
			tpr1, t85, f85)
	}
}
