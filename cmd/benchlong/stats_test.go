package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSlidingMaxCircular(t *testing.T) {
	x := []float64{1, 5, 2, 0, 3, 4}
	for n := 1; n <= 8; n++ {
		got := slidingMax(x, n)
		for i := range x {
			want := math.Inf(-1)
			for j := 0; j < min(n, len(x)); j++ {
				want = max(want, x[(i+j)%len(x)])
			}
			if got[i] != want {
				t.Fatalf("n=%d i=%d: got %v want %v", n, i, got[i], want)
			}
		}
	}
}

func TestBlockMaxGrowsWithN(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	stream := make([]float64, 20000)
	for i := range stream {
		stream[i] = sigmoid(rng.NormFloat64() - 6)
	}
	prev := 0.0
	for _, n := range []int{1, 16, 64, 256} {
		b := blockMax(stream, n, 4000, 0.85, rand.New(rand.NewPCG(3, 4)))
		if b.Q99 < prev {
			t.Fatalf("n=%d: q99 %v below n-smaller %v", n, b.Q99, prev)
		}
		prev = b.Q99
	}
}

// For i.i.d. logistic-normal scores the GEV extrapolation should land near
// the exact q99 of the maximum, Phi^-1(0.99^(1/n)) on the logit scale; the
// Gumbel one (a heavier tail than the normal's) must not be below it.
func TestGEVQuantileMatchesNormalMaxima(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	stream := make([]float64, 200000)
	for i := range stream {
		stream[i] = sigmoid(rng.NormFloat64() - 5)
	}
	g, ok := fitGEV(stream, 16)
	if !ok {
		t.Fatal("fit failed")
	}
	for _, n := range []int{64, 256, 1024} {
		exact := sigmoid(normInv(math.Pow(0.99, 1/float64(n))) - 5)
		for _, gumbel := range []bool{false, true} {
			got := g.Quantile99(n, gumbel)
			d := math.Abs(logit(got) - logit(exact))
			if gumbel {
				d = logit(exact) - logit(got)
			}
			if d > 0.35 {
				t.Errorf("n=%d gumbel=%v: %v (logit %.3f), exact %v (logit %.3f)", n, gumbel, got, logit(got), exact, logit(exact))
			}
		}
	}
}

// normInv by bisection on the error function (tests only).
func normInv(p float64) float64 {
	lo, hi := -10.0, 10.0
	for range 200 {
		mid := (lo + hi) / 2
		if 0.5*math.Erfc(-mid/math.Sqrt2) < p {
			lo = mid
		} else {
			hi = mid
		}
	}
	return (lo + hi) / 2
}

// splitOf must agree with bench/long/build.py split_of: the corpus field when
// present, else the last hex digit of SHA-256(id) (values computed with
// hashlib in Python).
func TestSplitOfMatchesBuilder(t *testing.T) {
	cases := map[string]string{
		"wiki-en-20000-0": splitHoldout, "logs-vi-50000-0": splitDev, "host-en-code": splitDev,
		"a.txt": splitDev, "report.txt": splitDev, "en-0123456789ab": splitHoldout, "vi-fedcba987654": splitHoldout, "x": splitDev,
	}
	for id, want := range cases {
		if got := splitOf(Doc{ID: id}); got != want {
			t.Errorf("%s: %s, want %s", id, got, want)
		}
	}
	// The corpus field wins: build.py hashes the payload id of attack documents.
	if got := splitOf(Doc{ID: "wiki-en-20000-0", Kind: "attack", Split: splitDev}); got != splitDev {
		t.Errorf("field ignored: %s", got)
	}
	var d Doc
	if err := json.Unmarshal([]byte(`{"id":"logs-vi-50000-0","kind":"benign","split":"holdout","text":"x","tokens":1}`), &d); err != nil {
		t.Fatal(err)
	}
	if splitOf(d) != splitHoldout {
		t.Errorf("split field not read: %+v", d)
	}
}

// The slices partition the documents: dev + holdout counts equal the totals
// of the unsliced table, and every sliced row carries its split.
func TestSplitSlicesPartitionTotals(t *testing.T) {
	var docs []Doc
	var res []docScore
	for i := range 40 {
		id := fmt.Sprintf("wiki-en-20000-%d", i)
		docs = append(docs, Doc{ID: id, Kind: "benign", Lang: "en", Genre: "wiki"})
		score := 0.1
		if i%5 == 0 {
			score = 0.9
		}
		res = append(res, docScore{tokens: 20000, units: map[string][]float64{"l2": {score, 0.2}}})
	}
	all := docFPR(docs, res, []string{"l2"}, "", func(Doc) bool { return true })
	if len(all) != 1 || all[0].Docs != 40 || all[0].Split != "" {
		t.Fatalf("all: %+v", all)
	}
	n, hit := 0, 0.0
	for _, s := range []string{splitDev, splitHoldout} {
		rows := docFPR(docs, res, []string{"l2"}, s, func(d Doc) bool { return splitOf(d) == s })
		if len(rows) != 1 || rows[0].Split != s || rows[0].Docs == 0 {
			t.Fatalf("%s: %+v", s, rows)
		}
		n += rows[0].Docs
		hit += rows[0].FPR * float64(rows[0].Docs)
	}
	if n != 40 || math.Abs(hit-all[0].FPR*40) > 1e-9 {
		t.Fatalf("slices do not partition the total: %d docs, %.3f hits vs %.3f", n, hit, all[0].FPR*40)
	}
}

func TestQuantileSummary(t *testing.T) {
	q := summarize([]float64{0.1, 0.9, 0.5, 0.3, 0.86}, 0.85)
	if q.N != 5 || q.P50 != 0.5 || q.Max != 0.9 || q.Above != 0.4 {
		t.Fatalf("%+v", q)
	}
}

func TestFusedUnitsMatchGatewayCuts(t *testing.T) {
	short := strings.Repeat("a", 2000)
	if u := fusedUnits(short); len(u) != 1 || u[0] != (span{0, 2000}) {
		t.Fatalf("short: %v", u)
	}
	// One segment: chunks every 1792 bytes, 2048 long, the last one ends the text.
	text := strings.Repeat("abcd ", 2000) // 10,000 bytes
	u := fusedUnits(text)
	for i, s := range u {
		if s.start != i*chunkStride {
			t.Fatalf("chunk %d starts at %d", i, s.start)
		}
	}
	if last := u[len(u)-1]; last.end != len(text) || len(u) != 6 {
		t.Fatalf("%d chunks, last %v", len(u), last)
	}
	// Several segments: every byte covered, segments overlap by 1 KiB,
	// cuts on rune boundaries.
	long := strings.Repeat("Tiếng Việt có dấu. ", 4000)
	segs := segmentSpans(long)
	if len(segs) < 3 {
		t.Fatalf("%d segments", len(segs))
	}
	for i, s := range segs {
		if s.end-s.start > segmentBytes || !utf8.RuneStart(long[s.start]) {
			t.Fatalf("segment %d: %v", i, s)
		}
		if i > 0 && segs[i-1].end-s.start > segmentOverlap+utf8.UTFMax {
			t.Fatalf("segments %d and %d overlap by %d", i-1, i, segs[i-1].end-s.start)
		}
	}
	covered := 0
	for _, c := range fusedUnits(long) {
		if c.start > covered {
			t.Fatalf("gap before %v", c)
		}
		covered = max(covered, c.end)
	}
	if covered != len(long) {
		t.Fatalf("covered %d of %d", covered, len(long))
	}
}

// TestFitGEVSaturatedStream: a benign stream whose block maxima are almost
// all the saturated score 1.0 (a classifier without a cap on long code or
// log documents) must still give finite GEV parameters and quantiles (the
// JSON report cannot hold NaN or Inf).
func TestFitGEVSaturatedStream(t *testing.T) {
	stream := make([]float64, 200000)
	for i := range stream {
		stream[i] = 1.0
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 40; i++ { // a few blocks below the saturation value
		j := rng.IntN(len(stream)/16) * 16
		for k := j; k < j+16; k++ {
			stream[k] = 0.3 + 0.5*rng.Float64()
		}
	}
	g, ok := fitGEV(stream, 16)
	if !ok {
		t.Skip("fit declined")
	}
	for _, v := range []float64{g.Xi, g.Alpha, g.K, g.GXi, g.GAlpha, g.Quantile99(1, false), g.Quantile99(1024, false), g.Quantile99(16, true)} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("non-finite GEV parameter or quantile: %+v, q1 %v, q1024 %v", g, g.Quantile99(1, false), g.Quantile99(1024, false))
		}
	}
}
