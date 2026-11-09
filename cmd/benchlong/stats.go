package main

import (
	"math"
	"math/rand/v2"
	"sort"
)

// quantile is the q-quantile of sorted (linear interpolation); NaN when empty.
func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	pos := q * float64(len(sorted)-1)
	i := int(pos)
	if i >= len(sorted)-1 {
		return sorted[len(sorted)-1]
	}
	f := pos - float64(i)
	return sorted[i]*(1-f) + sorted[i+1]*f
}

func sortedCopy(x []float64) []float64 {
	s := append([]float64(nil), x...)
	sort.Float64s(s)
	return s
}

// Quantiles summarises a score distribution (no raw scores are written out).
type Quantiles struct {
	N     int     `json:"n"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	P99   float64 `json:"p99"`
	P999  float64 `json:"p99_9"`
	Max   float64 `json:"max"`
	Above float64 `json:"frac_at_or_above_block"` // share of units at or above the block threshold
}

func summarize(x []float64, block float64) Quantiles {
	s := sortedCopy(x)
	q := Quantiles{N: len(s), P50: quantile(s, 0.5), P90: quantile(s, 0.9), P99: quantile(s, 0.99),
		P999: quantile(s, 0.999), Max: quantile(s, 1)}
	if len(s) > 0 {
		k := sort.SearchFloat64s(s, block)
		q.Above = float64(len(s)-k) / float64(len(s))
	}
	return q
}

// slidingMax returns, for every start i of the circular sequence x, the
// maximum of x[i], ..., x[i+n-1] (indices mod len(x)). O(len(x)) with a
// monotonic deque.
func slidingMax(x []float64, n int) []float64 {
	m := len(x)
	if m == 0 {
		return nil
	}
	if n >= m {
		mx := x[0]
		for _, v := range x {
			mx = max(mx, v)
		}
		out := make([]float64, m)
		for i := range out {
			out[i] = mx
		}
		return out
	}
	out := make([]float64, m)
	dq := make([]int, 0, n) // indices into the doubled sequence, values decreasing
	at := func(j int) float64 { return x[j%m] }
	for j := 0; j < m+n-1; j++ {
		for len(dq) > 0 && at(dq[len(dq)-1]) <= at(j) {
			dq = dq[:len(dq)-1]
		}
		dq = append(dq, j)
		if dq[0] <= j-n {
			dq = dq[1:]
		}
		if start := j - n + 1; start >= 0 {
			out[start] = at(dq[0])
		}
	}
	return out
}

// BlockMax is the distribution of the maximum score over n contiguous units
// (windows or chunks) of benign text: a circular moving-block bootstrap of
// the concatenated benign stream.
type BlockMax struct {
	N int `json:"n"`
	// Q99 is the 99th percentile of the maximum over n units from B random
	// block starts (seeded): the threshold that keeps a benign text of n
	// units under 1% false positives.
	Q99 float64 `json:"q99"`
	// FPRBlock is the share of all block starts whose maximum reaches the
	// block threshold: the false-positive rate of an n-unit benign text.
	FPRBlock float64 `json:"fpr_at_block"`
	// Short is true when n is more than a fifth of the stream: the blocks
	// then overlap so much that the estimate is weak.
	Short bool `json:"short_stream,omitempty"`
}

func blockMax(stream []float64, n, draws int, block float64, rng *rand.Rand) BlockMax {
	sm := slidingMax(stream, n)
	out := BlockMax{N: n, Short: n*5 > len(stream)}
	if len(sm) == 0 {
		out.Q99, out.FPRBlock = math.NaN(), math.NaN()
		return out
	}
	hit := 0
	for _, v := range sm {
		if v >= block {
			hit++
		}
	}
	out.FPRBlock = float64(hit) / float64(len(sm))
	sample := make([]float64, draws)
	for i := range sample {
		sample[i] = sm[rng.IntN(len(sm))]
	}
	sort.Float64s(sample)
	out.Q99 = quantile(sample, 0.99)
	return out
}

// GEV is a generalized extreme value fit (Hosking's L-moment estimator) of
// the maxima of non-overlapping blocks of M units, on the logit scale.
// K = 0 is the Gumbel case; Hosking's sign convention (K > 0: bounded tail).
type GEV struct {
	M     int     `json:"block"`
	Xi    float64 `json:"xi"`
	Alpha float64 `json:"alpha"`
	K     float64 `json:"k"`
	// Gumbel parameters fitted to the same maxima (K forced to 0).
	GXi    float64 `json:"gumbel_xi"`
	GAlpha float64 `json:"gumbel_alpha"`
	Blocks int     `json:"blocks"`
}

const eulerGamma = 0.5772156649015329

func logit(p float64) float64 {
	p = min(max(p, 1e-9), 1-1e-9)
	return math.Log(p / (1 - p))
}

func sigmoid(z float64) float64 { return 1 / (1 + math.Exp(-z)) }

// fitGEV fits the maxima of consecutive blocks of m units of stream (logit
// scale). ok is false with fewer than 20 blocks.
func fitGEV(stream []float64, m int) (GEV, bool) {
	var maxima []float64
	for i := 0; i+m <= len(stream); i += m {
		mx := math.Inf(-1)
		for _, v := range stream[i : i+m] {
			mx = max(mx, logit(v))
		}
		maxima = append(maxima, mx)
	}
	g := GEV{M: m, Blocks: len(maxima)}
	if len(maxima) < 20 {
		return g, false
	}
	sort.Float64s(maxima)
	n := float64(len(maxima))
	var b0, b1, b2 float64
	for i, x := range maxima {
		fi := float64(i)
		b0 += x
		b1 += fi / (n - 1) * x
		b2 += fi * (fi - 1) / ((n - 1) * (n - 2)) * x
	}
	b0, b1, b2 = b0/n, b1/n, b2/n
	l1, l2, l3 := b0, 2*b1-b0, 6*b2-6*b1+b0
	if l2 <= 0 {
		return g, false
	}
	g.GAlpha = l2 / math.Ln2
	g.GXi = l1 - eulerGamma*g.GAlpha
	t3 := l3 / l2
	c := 2/(3+t3) - math.Ln2/math.Log(3)
	k := 7.8590*c + 2.9554*c*c
	if math.Abs(k) < 1e-6 {
		g.K, g.Alpha, g.Xi = 0, g.GAlpha, g.GXi
		return g, true
	}
	gam := math.Gamma(1 + k)
	g.K = k
	g.Alpha = l2 * k / ((1 - math.Pow(2, -k)) * gam)
	g.Xi = l1 - g.Alpha*(1-gam)/k
	return g, true
}

// Quantile99 is the 99th percentile of the maximum over n units, from the
// GEV (gumbel=false) or the Gumbel fit, as a probability.
func (g GEV) Quantile99(n int, gumbel bool) float64 {
	// max over n units = max over n/M blocks: F_n = F_M^(n/M), so the
	// 0.99 quantile of the n-unit maximum is the 0.99^(M/n) quantile of a block maximum.
	y := -math.Log(math.Pow(0.99, float64(g.M)/float64(n))) // -ln F
	if gumbel || g.K == 0 {
		return sigmoid(g.GXi - g.GAlpha*math.Log(y))
	}
	return sigmoid(g.Xi + g.Alpha/g.K*(1-math.Pow(y, g.K)))
}
