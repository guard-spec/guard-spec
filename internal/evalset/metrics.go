package evalset

import (
	"math"
	"sort"
	"time"
)

// ROCAUC is the probability that a random positive scores above a random
// negative, counting ties as one half (Mann-Whitney U). It returns NaN when
// either class is empty.
func ROCAUC(pos, neg []float64) float64 {
	if len(pos) == 0 || len(neg) == 0 {
		return math.NaN()
	}
	type item struct {
		s   float64
		pos bool
	}
	all := make([]item, 0, len(pos)+len(neg))
	for _, s := range pos {
		all = append(all, item{s, true})
	}
	for _, s := range neg {
		all = append(all, item{s, false})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].s < all[j].s })

	// Sum of average ranks (1-based) of the positives.
	var rankSum float64
	for i := 0; i < len(all); {
		j := i
		for j < len(all) && all[j].s == all[i].s {
			j++
		}
		avg := float64(i+1+j) / 2 // mean of ranks i+1..j
		for k := i; k < j; k++ {
			if all[k].pos {
				rankSum += avg
			}
		}
		i = j
	}
	np, nn := float64(len(pos)), float64(len(neg))
	return (rankSum - np*(np+1)/2) / (np * nn)
}

// Rates returns the share of positives and of negatives scoring >= threshold.
// A rate is NaN when its class is empty.
func Rates(pos, neg []float64, threshold float64) (tpr, fpr float64) {
	return shareAtLeast(pos, threshold), shareAtLeast(neg, threshold)
}

func shareAtLeast(xs []float64, t float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	n := 0
	for _, x := range xs {
		if x >= t {
			n++
		}
	}
	return float64(n) / float64(len(xs))
}

// ThresholdAtFPR returns the lowest threshold t (flag when score >= t) whose
// false-positive rate on neg is <= budget. Lower thresholds flag more, so this
// is the threshold with the best TPR inside the budget. The threshold sits
// just above the highest negative score that must stay unflagged; it is -Inf
// when the budget allows flagging every negative, and +Inf when neg is empty.
func ThresholdAtFPR(neg []float64, budget float64) float64 {
	if len(neg) == 0 {
		return math.Inf(1)
	}
	sorted := append([]float64(nil), neg...)
	sort.Float64s(sorted)
	allowed := int(math.Floor(budget*float64(len(sorted)) + 1e-9))
	// Thresholds just above sorted[i-1] flag the len-i negatives from index i
	// on; only boundaries between distinct scores are reachable.
	for i := 0; i <= len(sorted); i++ {
		if i > 0 && i < len(sorted) && sorted[i] == sorted[i-1] {
			continue
		}
		if len(sorted)-i <= allowed {
			if i == 0 {
				return math.Inf(-1)
			}
			return math.Nextafter(sorted[i-1], math.Inf(1))
		}
	}
	return math.Inf(1) // unreachable: i == len(sorted) always qualifies
}

// TPRAtFPR returns the TPR, achieved FPR and threshold at the FPR budget.
func TPRAtFPR(pos, neg []float64, budget float64) (tpr, fpr, threshold float64) {
	threshold = ThresholdAtFPR(neg, budget)
	tpr, fpr = Rates(pos, neg, threshold)
	return tpr, fpr, threshold
}

// Percentile returns the p-th percentile (0-100) by nearest rank.
func Percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	rank := int(math.Ceil(p / 100 * float64(len(s))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(s) {
		rank = len(s)
	}
	return s[rank-1]
}
