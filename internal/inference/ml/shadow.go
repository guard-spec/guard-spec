// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// Shadow mode runs a candidate classifier on the same traffic as the active
// one and records what it would have scored, without ever changing a decision.
//
// It is asynchronous: the active fuser scores a text and returns at once; the
// candidate then scores the same text on its own goroutine and its own ONNX
// limiter (so it never holds a slot an active request waits for), and its L2
// verdict is fused with the active run's L1 and L3 scores (fusion.Replace).
// The request's Recorder collects both sides; the gateway waits for it, up to
// ShadowConfig.Timeout, only when it writes the audit row, which is already
// off the response path. At most MaxInFlight candidate runs are in flight; a
// text that finds them all busy is not compared (status skipped), so a burst
// of traffic cannot queue up shadow work.

// Environment variables of shadow mode.
const (
	EnvShadowModel       = "SHADOW_L2_MODEL"     // candidate classifier, name[@version]
	EnvShadowDir         = "SHADOW_L2_MODEL_DIR" // candidate directory; wins over SHADOW_L2_MODEL
	EnvShadowTimeout     = "SHADOW_TIMEOUT"      // budget of one request's comparison (default 2s)
	EnvShadowSample      = "SHADOW_SAMPLE"       // share of requests compared, 0..1 (default 1)
	EnvShadowMaxInFlight = "SHADOW_MAX_INFLIGHT" // concurrent candidate runs (default NumCPU/2, at least 1)
	// ShadowOff as ReloadRequest.Shadow stops shadow mode.
	ShadowOff            = "off"
	defaultShadowTimeout = 2 * time.Second
	maxShadowTimeout     = 60 * time.Second
)

// ShadowConfig selects the candidate classifier. Shadow mode is off when both
// Model and Dir are empty.
type ShadowConfig struct {
	Model       string
	Dir         string
	Timeout     time.Duration
	Sample      float64
	MaxInFlight int
}

// Enabled reports whether a candidate is configured.
func (c ShadowConfig) Enabled() bool { return c.Model != "" || c.Dir != "" }

func shadowConfigFromEnv(get func(string) string) (ShadowConfig, error) {
	c := ShadowConfig{
		Model:       strings.TrimSpace(get(EnvShadowModel)),
		Dir:         strings.TrimSpace(get(EnvShadowDir)),
		Timeout:     defaultShadowTimeout,
		Sample:      1,
		MaxInFlight: max(1, runtime.NumCPU()/2),
	}
	if c.Model != "" {
		if _, _, err := onnx.ParseRef(c.Model); err != nil {
			return c, fmt.Errorf("%s: %w", EnvShadowModel, err)
		}
	}
	if v := strings.TrimSpace(get(EnvShadowTimeout)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > maxShadowTimeout {
			return c, fmt.Errorf("%s must be a duration in (0, %s]", EnvShadowTimeout, maxShadowTimeout)
		}
		c.Timeout = d
	}
	if v := strings.TrimSpace(get(EnvShadowSample)); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 || f > 1 {
			return c, fmt.Errorf("%s must be a number in [0, 1]", EnvShadowSample)
		}
		c.Sample = f
	}
	if v := strings.TrimSpace(get(EnvShadowMaxInFlight)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, fmt.Errorf("%s must be a whole number, 1 or more", EnvShadowMaxInFlight)
		}
		c.MaxInFlight = n
	}
	return c, nil
}

// Shadow statuses of a request (ShadowResult.Status).
const (
	ShadowOK      = "ok"      // every scanned text was scored by both models
	ShadowTimeout = "timeout" // the candidate did not finish within the budget
	ShadowError   = "error"   // the candidate failed on a text
	ShadowSkipped = "skipped" // every shadow slot was busy, so a text was not compared
)

// ShadowResult is one request's comparison. Scores are the largest fused
// injection score over every text the detector scanned for the request, for
// each side; L2 scores are the calibrated classifier scores (fusion.Missing
// when the layer did not run, e.g. skipped by the cascade).
type ShadowResult struct {
	Status      string
	ActiveModel string
	ShadowModel string
	ActiveScore float64
	ShadowScore float64
	ActiveL2    float64
	ShadowL2    float64
	Texts       int // texts compared
}

// Recorder collects the comparison of one request. Put it in the request's
// context with WithRecorder before scanning; read it with Wait.
type Recorder struct {
	mu  sync.Mutex
	wg  sync.WaitGroup
	res ShadowResult
	n   int // texts submitted
	bad map[string]int
}

// NewRecorder starts an empty comparison.
func NewRecorder() *Recorder {
	return &Recorder{res: ShadowResult{ActiveScore: fusion.Missing, ShadowScore: fusion.Missing,
		ActiveL2: fusion.Missing, ShadowL2: fusion.Missing}, bad: map[string]int{}}
}

type recorderKey struct{}

// WithRecorder returns ctx carrying rec: scans under it are compared.
func WithRecorder(ctx context.Context, rec *Recorder) context.Context {
	return context.WithValue(ctx, recorderKey{}, rec)
}

func recorderFrom(ctx context.Context) *Recorder {
	rec, _ := ctx.Value(recorderKey{}).(*Recorder)
	return rec
}

// start counts a text to compare; finish (or fail) must follow.
func (r *Recorder) start() {
	r.mu.Lock()
	r.n++
	r.mu.Unlock()
	r.wg.Add(1)
}

func (r *Recorder) finish(active, shadow fusion.Result, activeModel, shadowModel string) {
	defer r.wg.Done()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.res.ActiveModel, r.res.ShadowModel = activeModel, shadowModel
	r.res.ActiveScore = max(r.res.ActiveScore, active.Score)
	r.res.ShadowScore = max(r.res.ShadowScore, shadow.Score)
	r.res.ActiveL2 = max(r.res.ActiveL2, active.Layers[fusion.L2])
	r.res.ShadowL2 = max(r.res.ShadowL2, shadow.Layers[fusion.L2])
	r.res.Texts++
}

func (r *Recorder) fail(status, activeModel, shadowModel string) {
	defer r.wg.Done()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.res.ActiveModel, r.res.ShadowModel = activeModel, shadowModel
	r.bad[status]++
}

// Wait waits up to timeout for the candidate runs of this request and returns
// the comparison. Status is "" when nothing was compared (the request was
// refused before the detector ran, or shadow mode is off). Runs still going
// after the timeout make it ShadowTimeout; they finish on their own.
func (r *Recorder) Wait(timeout time.Duration) ShadowResult {
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	timedOut := false
	select {
	case <-done:
	case <-timer.C:
		timedOut = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	res := r.res
	switch {
	case r.n == 0:
		res.Status = ""
	case r.bad[ShadowError] > 0:
		res.Status = ShadowError
	case timedOut || r.bad[ShadowTimeout] > 0:
		res.Status = ShadowTimeout
	case r.bad[ShadowSkipped] > 0:
		res.Status = ShadowSkipped
	default:
		res.Status = ShadowOK
	}
	return res
}

// shadowModel is a loaded candidate and how its verdict is fused.
type shadowModel struct {
	m    *L2Model
	comb *fusion.LogReg // nil: max
}

// newShadow pairs a candidate with the fusion weights for the stack's layers
// plus L2 (as the active fuser would use them with this classifier).
func (s *Stack) newShadow(m *L2Model) *shadowModel {
	sh := &shadowModel{m: m}
	if s.cfg.Fusion == "logreg" {
		active := s.Active
		active[fusion.L2] = true
		if lr, ok := m.Cal.LogReg[LayerKey(active)]; ok {
			sh.comb = &lr
		}
	}
	return sh
}

// compare scores text with the candidate and re-fuses the active result.
// The cascade decides for both: when it skipped L2 for the active model, the
// candidate is not run and scores the same.
func (sh *shadowModel) compare(ctx context.Context, text string, active fusion.Result) (fusion.Result, error) {
	if active.Cascaded {
		return active, nil
	}
	lr, err := sh.m.Layer.Score(ctx, text)
	if err != nil {
		return fusion.Result{}, err
	}
	return fusion.Replace(active, fusion.L2, lr, nil, sh.m.Cal.Platt, sh.comb), nil
}

// runShadow compares one text in the background. g must be held by the
// caller; the goroutine holds it again until it is done, so a reload never
// closes the candidate under it.
func (l *Live) runShadow(ctx context.Context, g *generation, rec *Recorder, text string, active fusion.Result) {
	sh := g.shadow
	rec.start()
	activeModel, shadowModel := g.l2.Label(), sh.m.Label()
	select {
	case l.slots <- struct{}{}:
	default:
		rec.fail(ShadowSkipped, activeModel, shadowModel)
		return
	}
	g.inflight.Add(1)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.shadowCfg.Timeout)
	go func() {
		defer func() { <-l.slots }()
		defer g.inflight.Done()
		defer cancel()
		res, err := sh.compare(ctx, text, active)
		switch {
		case err == nil:
			rec.finish(active, res, activeModel, shadowModel)
		case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
			rec.fail(ShadowTimeout, activeModel, shadowModel)
		default:
			rec.fail(ShadowError, activeModel, shadowModel)
		}
	}()
}
