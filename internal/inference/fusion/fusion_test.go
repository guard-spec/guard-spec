package fusion

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/promptshield/promptshield/internal/inference/rules"
	"github.com/promptshield/promptshield/internal/sanitizer"
)

type fixed struct {
	s   float64
	cat string
	err error
}

func (f fixed) Score(context.Context, string) (LayerResult, error) {
	if f.err != nil {
		return LayerResult{}, f.err
	}
	return LayerResult{Score: f.s, Category: f.cat, Categories: map[string]float64{f.cat: f.s}, Rules: []string{f.cat}}, nil
}

func TestFuseTakesMaxOfCalibratedLayers(t *testing.T) {
	f := &Fuser{}
	f.Set(L1, fixed{s: 0.4, cat: "jailbreak"}, Identity)
	f.Set(L2, fixed{s: 0.9, cat: "direct_injection"}, Identity)
	r := f.Score(context.Background(), "x")
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	if !near(r.Score, 0.9) || r.Category != "direct_injection" {
		t.Fatalf("got %+v", r)
	}
	if !near(r.Layers[L1], 0.4) || !near(r.Layers[L2], 0.9) || r.Layers[L3] != Missing {
		t.Fatalf("layers %+v", r.Layers)
	}
	if !near(r.Categories["jailbreak"], 0.4) || !near(r.Categories["direct_injection"], 0.9) {
		t.Fatalf("categories %+v", r.Categories)
	}
}

func TestMissingAndFailingLayersDegrade(t *testing.T) {
	f := &Fuser{}
	f.Set(L1, fixed{s: 0.7, cat: "jailbreak"}, Identity)
	f.Set(L2, fixed{err: errors.New("model crashed")}, Identity)
	r := f.Score(context.Background(), "x")
	if r.Score != 0.7 || r.Layers[L2] != Missing || r.Layers[L3] != Missing {
		t.Fatalf("got %+v", r)
	}
	empty := (&Fuser{}).Score(context.Background(), "x")
	if empty.Score != 0 || empty.Category != "" {
		t.Fatalf("no layers: %+v", empty)
	}
}

func TestCalibrationApply(t *testing.T) {
	if got := Identity.Apply(0.3); math.Abs(got-0.3) > 1e-9 {
		t.Errorf("identity: %v", got)
	}
	c := Calibration{A: 2, B: 0}
	if c.Apply(0.8) <= 0.8 || c.Apply(0.2) >= 0.2 {
		t.Error("A>1 must sharpen")
	}
}

func TestFitPlattRecoversSeparation(t *testing.T) {
	var s []float64
	var y []bool
	for i := 0; i < 50; i++ {
		s = append(s, 0.9, 0.1)
		y = append(y, true, false)
	}
	c := FitPlatt(s, y)
	if c.Apply(0.9) < 0.9 || c.Apply(0.1) > 0.1 {
		t.Errorf("fit %+v: p(0.9)=%v p(0.1)=%v", c, c.Apply(0.9), c.Apply(0.1))
	}
}

type calRow struct {
	Text  string `json:"text"`
	Label string `json:"label"`
	Lang  string `json:"lang"`
}

func loadCalibration(t *testing.T) []calRow {
	t.Helper()
	f, err := os.Open("testdata/calibration.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows []calRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r calRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	return rows
}

// TestL1CalibrationIsFitted refits the L1 Platt scaling on the calibration
// split and checks DefaultL1Calibration matches. Run with -v to print the fit.
func TestL1CalibrationIsFitted(t *testing.T) {
	rows := loadCalibration(t)
	e := rules.New()
	var s []float64
	var y []bool
	for _, r := range rows {
		cl, _, err := sanitizer.Sanitize(r.Text)
		if err != nil {
			t.Fatal(err)
		}
		s = append(s, e.Score(cl).Score)
		y = append(y, r.Label == "attack")
	}
	c := FitPlatt(s, y)
	t.Logf("fitted L1 calibration on %d rows: A=%.3f B=%.3f", len(rows), c.A, c.B)
	if math.Abs(c.A-DefaultL1Calibration.A) > 0.01 || math.Abs(c.B-DefaultL1Calibration.B) > 0.01 {
		t.Errorf("DefaultL1Calibration = %+v, refit gives A=%.3f B=%.3f; update calibration.go", DefaultL1Calibration, c.A, c.B)
	}
}

// fingerprint mirrors normalize_for_fingerprint in eval/build/build.py.
func fingerprint(s string) string {
	s = norm.NFC.String(s)
	s = strings.NewReplacer("đ", "d", "Đ", "D").Replace(s)
	var b strings.Builder
	for _, r := range norm.NFD.String(s) {
		if !unicode.Is(unicode.Mn, r) {
			b.WriteRune(r)
		}
	}
	s = strings.Join(strings.Fields(strings.ToLower(b.String())), " ")
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestCalibrationSplitIsNotEval guards against fitting on eval rows.
func TestCalibrationSplitIsNotEval(t *testing.T) {
	b, err := os.ReadFile("../../../eval/fingerprints.txt")
	if err != nil {
		t.Skip("eval fingerprints not present")
	}
	eval := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			eval[l] = true
		}
	}
	// The fingerprint must reproduce eval's: the first eval row is listed.
	if raw, err := os.ReadFile("../../../eval/data/en.jsonl"); err == nil {
		var first calRow
		if err := json.Unmarshal([]byte(strings.SplitN(string(raw), "\n", 2)[0]), &first); err != nil {
			t.Fatal(err)
		}
		if !eval[fingerprint(first.Text)] {
			t.Fatal("fingerprint() does not match eval/build/build.py")
		}
	}
	rows := loadCalibration(t)
	att := 0
	for _, r := range rows {
		if eval[fingerprint(r.Text)] {
			t.Errorf("calibration row is in eval/: %q", r.Text)
		}
		if r.Label == "attack" {
			att++
		}
	}
	if len(rows) < 100 || att == 0 || att == len(rows) {
		t.Errorf("calibration split too small or one-sided: %d rows, %d attacks", len(rows), att)
	}
}
