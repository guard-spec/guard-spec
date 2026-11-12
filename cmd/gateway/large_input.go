// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// Large inputs (RF-320915ea).
//
// A request is large when its scanned text goes past today's limits: direct
// text over 16 chunks of about 2 KB (28,928 bytes), more than 128 KiB of tool
// results, documents and tool descriptions, or more than 1 MiB of earlier
// turns to scan again. With MAX_SCAN_TOKENS unset (the default) such a
// request is refused with 413, as before. With it set, the request waits for
// the large-input lane, its tokens are counted, and a request within the cap
// is scanned: its texts past the short path's limit on the long path
// (inference.Runner.ScanLong), under the lane's own model limiter, the others
// on the short path as before. Every byte is scanned; a request the gateway
// cannot scan is never forwarded.
//
// The lane admits INFERENCE_LARGE_MAX_CONCURRENCY requests at a time, at most
// LARGE_SCAN_ORG_CONCURRENCY of one org; the others queue for up to
// LARGE_SCAN_QUEUE_TIMEOUT and then get 429 with Retry-After. Requests that
// are not large never enter the lane, so they never wait behind a large one.

// Environment variables of large inputs.
const (
	envMaxScanTokens       = "MAX_SCAN_TOKENS"
	envLargeConcurrency    = "INFERENCE_LARGE_MAX_CONCURRENCY"
	envLargeOrgConcurrency = "LARGE_SCAN_ORG_CONCURRENCY"
	envLargeQueueTimeout   = "LARGE_SCAN_QUEUE_TIMEOUT"
	envMaxRequestBytes     = "MAX_REQUEST_BYTES"
)

const (
	defaultLargeQueueTimeout = 30 * time.Second
	// defaultMaxRequestBytes is Fiber's default body limit, kept.
	defaultMaxRequestBytes = 4 << 20
	// largeQueuePerSlot bounds the queue: requests waiting per lane slot.
	// A waiting request holds its body in memory; past this the lane answers
	// 429 at once.
	largeQueuePerSlot = 8
	// largeBatch is the number of token windows per model run on the long
	// path.
	largeBatch = 16
	// historyBytesPerToken scales MAX_SCAN_TOKENS to the byte limit of
	// earlier turns, like maxHistoryBytes to maxUntrustedBytes: 8 times
	// the cap, 4 bytes per token.
	historyBytesPerToken = 8 * 4
)

// defaultLargeConcurrency is a quarter of the CPUs the process may use
// (GOMAXPROCS, which follows a container's CPU limit), at least one.
// Long-path scans are CPU-bound batch work: a quarter of the cores keeps
// three quarters for the short path, which serves most requests and is what
// users wait on interactively, while large requests still make progress.
func defaultLargeConcurrency() int { return max(1, runtime.GOMAXPROCS(0)/4) }

// largeConfig is the large-input lane's configuration.
type largeConfig struct {
	Concurrency     int           // INFERENCE_LARGE_MAX_CONCURRENCY
	OrgConcurrency  int           // LARGE_SCAN_ORG_CONCURRENCY
	QueueTimeout    time.Duration // LARGE_SCAN_QUEUE_TIMEOUT
	MaxRequestBytes int           // MAX_REQUEST_BYTES
}

// loadLargeConfig reads the lane's variables.
func loadLargeConfig(env func(string) string) (largeConfig, error) {
	cfg := largeConfig{Concurrency: defaultLargeConcurrency(), QueueTimeout: defaultLargeQueueTimeout,
		MaxRequestBytes: defaultMaxRequestBytes}
	ints := []struct {
		name     string
		dst      *int
		min, max int
	}{
		{envLargeConcurrency, &cfg.Concurrency, 1, 1024},
		{envLargeOrgConcurrency, &cfg.OrgConcurrency, 1, 1024},
		{envMaxRequestBytes, &cfg.MaxRequestBytes, 1 << 10, 1 << 30},
	}
	for _, v := range ints {
		s := strings.TrimSpace(env(v.name))
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < v.min || n > v.max {
			return largeConfig{}, fmt.Errorf("%s must be a whole number from %d to %d", v.name, v.min, v.max)
		}
		*v.dst = n
	}
	if cfg.OrgConcurrency == 0 {
		cfg.OrgConcurrency = max(1, cfg.Concurrency/2)
	}
	cfg.OrgConcurrency = min(cfg.OrgConcurrency, cfg.Concurrency)
	if s := strings.TrimSpace(env(envLargeQueueTimeout)); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < time.Second || d > 10*time.Minute {
			return largeConfig{}, fmt.Errorf("%s must be a duration from 1s to 10m", envLargeQueueTimeout)
		}
		cfg.QueueTimeout = d
	}
	return cfg, nil
}

// parseMaxScanTokens reads MAX_SCAN_TOKENS: 0 (unset) keeps today's limits.
func parseMaxScanTokens(env func(string) string) (int, error) {
	s := strings.TrimSpace(env(envMaxScanTokens))
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > indirect.MaxScanTokensLimit {
		return 0, fmt.Errorf("%s must be a whole number from 0 (today's limits) to %d", envMaxScanTokens, indirect.MaxScanTokensLimit)
	}
	return n, nil
}

// largeLaneFor returns the lane when MAX_SCAN_TOKENS opens the long path, else
// nil, and logs the configuration.
func largeLaneFor(maxScanTokens int, cfg largeConfig) *largeLane {
	if maxScanTokens <= 0 {
		slog.Info("large inputs", "max_scan_tokens", "unset: requests past today's limits get 413",
			"max_request_bytes", cfg.MaxRequestBytes)
		return nil
	}
	slog.Info("large inputs", "max_scan_tokens", maxScanTokens, "concurrency", cfg.Concurrency,
		"org_concurrency", cfg.OrgConcurrency, "queue_timeout", cfg.QueueTimeout, "max_request_bytes", cfg.MaxRequestBytes)
	if maxScanTokens*4 > cfg.MaxRequestBytes {
		slog.Warn("MAX_REQUEST_BYTES is smaller than MAX_SCAN_TOKENS of text (about 4 bytes a token): "+
			"bodies that large are refused with 413 before they are scanned", "max_request_bytes", cfg.MaxRequestBytes)
	}
	return newLargeLane(cfg)
}

// errScanBusy refuses a large request the lane could not take in time.
var errScanBusy = errors.New("the gateway is busy scanning other large requests; retry later")

// scanBusy is errScanBusy with the Retry-After to send.
type scanBusy struct{ after int }

func (e scanBusy) Error() string        { return errScanBusy.Error() }
func (e scanBusy) Is(target error) bool { return target == errScanBusy }

// retryAfterSeconds is the Retry-After of a busy lane's refusal.
func retryAfterSeconds(err error) int {
	var b scanBusy
	if errors.As(err, &b) {
		return b.after
	}
	return int(defaultLargeQueueTimeout / time.Second)
}

// largeLane admits large requests: Cap at a time, OrgCap per org, the rest
// queued first come, first served, for up to timeout.
type largeLane struct {
	lim      *onnx.Limiter // the long path's model runs
	orgCap   int
	timeout  time.Duration
	maxQueue int

	mu      sync.Mutex
	running int
	perOrg  map[uuid.UUID]int
	queue   []*laneWaiter
}

type laneWaiter struct {
	org     uuid.UUID
	ready   chan struct{}
	granted bool
}

func newLargeLane(cfg largeConfig) *largeLane {
	return &largeLane{lim: onnx.NewLimiter(cfg.Concurrency), orgCap: max(1, cfg.OrgConcurrency),
		timeout: cfg.QueueTimeout, maxQueue: largeQueuePerSlot * cfg.Concurrency, perOrg: map[uuid.UUID]int{}}
}

// retryAfter is the Retry-After of a 429 from the lane, in seconds.
func (l *largeLane) retryAfter() int { return max(1, int(math.Ceil(l.timeout.Seconds()))) }

// free reports whether org can start now; l.mu is held.
func (l *largeLane) free(org uuid.UUID) bool {
	return l.running < l.lim.Cap() && l.perOrg[org] < l.orgCap
}

// acquire waits for the lane. The release it returns must be called once.
func (l *largeLane) acquire(ctx context.Context, org uuid.UUID) (func(), error) {
	start := time.Now()
	l.mu.Lock()
	if l.free(org) {
		l.start(org)
		l.mu.Unlock()
		metrics.ScanQueueWait.WithLabelValues("admitted").Observe(0)
		return l.releaser(org), nil
	}
	if len(l.queue) >= l.maxQueue {
		l.mu.Unlock()
		metrics.ScanQueueWait.WithLabelValues("full").Observe(0)
		return nil, scanBusy{after: l.retryAfter()}
	}
	w := &laneWaiter{org: org, ready: make(chan struct{})}
	l.queue = append(l.queue, w)
	l.mu.Unlock()

	timer := time.NewTimer(l.timeout)
	defer timer.Stop()
	var err error
	select {
	case <-w.ready:
	case <-timer.C:
		err = scanBusy{after: l.retryAfter()}
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		l.mu.Lock()
		if !w.granted {
			for i, q := range l.queue {
				if q == w {
					l.queue = append(l.queue[:i], l.queue[i+1:]...)
					break
				}
			}
			l.mu.Unlock()
			outcome := "timeout"
			if !errors.Is(err, errScanBusy) {
				outcome = "canceled"
			}
			metrics.ScanQueueWait.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
			return nil, err
		}
		l.mu.Unlock() // granted just as we gave up: take it
	}
	metrics.ScanQueueWait.WithLabelValues("admitted").Observe(time.Since(start).Seconds())
	return l.releaser(org), nil
}

func (l *largeLane) start(org uuid.UUID) {
	l.running++
	l.perOrg[org]++
}

func (l *largeLane) releaser(org uuid.UUID) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.running--
			if l.perOrg[org]--; l.perOrg[org] <= 0 {
				delete(l.perOrg, org)
			}
			// Hand the freed slot to the first waiter that may start.
			for i := 0; i < len(l.queue); {
				w := l.queue[i]
				if !l.free(w.org) {
					i++
					continue
				}
				l.start(w.org)
				w.granted = true
				close(w.ready)
				l.queue = append(l.queue[:i], l.queue[i+1:]...)
			}
		})
	}
}

// waiting is the number of queued requests (tests).
func (l *largeLane) waiting() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.queue)
}

// scanLimits is what one request may scan (scanConfig with the org's
// settings), and when a long text may stop early.
type scanLimits struct {
	// long: the long path is on (MAX_SCAN_TOKENS > 0 and a lane).
	long bool
	// maxTokens is the request's token cap (0: none, byte limits only).
	maxTokens int
	// direct and indirect stop a long text's scan once a window reaches
	// them: the request is refused anyway. indirect is 0 in redact mode,
	// where every part must be scored.
	direct, indirect float64
}

// limitsFor returns the request's limits under cfg.
func (gw gateway) limitsFor(cfg scanConfig) scanLimits {
	lim := scanLimits{long: gw.large != nil && cfg.MaxScanTokens > 0, maxTokens: cfg.ScanTokens,
		direct: cfg.injectionThreshold()}
	if cfg.IndirectAction != indirect.ActionRedact {
		lim.indirect = cfg.IndirectThreshold
	}
	return lim
}

// withinTokens reports whether texts hold at most limit tokens, as
// MAX_SCAN_TOKENS counts them. A text has at most one token per byte, plus
// one, so texts whose bytes fit are not tokenized.
func (gw gateway) withinTokens(texts []string, limit int) (bool, error) {
	bytes := 0
	for _, t := range texts {
		bytes += len(t) + 1
	}
	if bytes <= limit {
		return true, nil
	}
	n, err := gw.tokensOf(texts, limit)
	return n <= limit, err
}

// tokensOf counts the tokens of texts; it stops once they pass limit (0: no
// limit).
func (gw gateway) tokensOf(texts []string, limit int) (int, error) {
	n := 0
	for _, t := range texts {
		c, err := gw.runner.CountTokens(t)
		if err != nil {
			return 0, fmt.Errorf("count tokens: %w", err)
		}
		if n += c; limit > 0 && n > limit {
			break
		}
	}
	return n, nil
}

// scanSizes is what a request still has to scan: its texts the scan cache
// had no verdict of (segment or long-path).
type scanSizes struct {
	joined    string        // user, system and tool-call text, joined
	alone     []string      // direct texts scored alone (a Messages system prompt)
	untrusted []pendingText // tool results and documents
	tools     []string      // tool descriptions
	// untrustedBytes counts the untrusted texts of this turn and the tool
	// descriptions; historyBytes the untrusted texts of earlier turns.
	untrustedBytes, historyBytes int
}

// pendingText is an untrusted text to scan.
type pendingText struct {
	text    string
	history bool // from an earlier turn
	// adjust is the scanner's per-window adjustment for the text's source
	// (code corroboration), so that the long path scores it as Scan will.
	adjust inference.ChunkAdjust
}

// scanRun is how a request's texts are scanned.
type scanRun struct {
	// ctx is gw.base for a request within today's limits; for a large one
	// it carries the long scan and the lane's model limiter.
	ctx   context.Context
	large bool
	done  func() // releases the lane; call once
}

// admitScan decides how the request is scanned. Within today's limits it is
// scanned as before, after a check of its token cap when there is one. Past
// them it is refused (ErrInputTooLong) unless the long path is on; then it
// waits for the lane (errScanBusy after the queue timeout), its tokens are
// counted against the cap (errOverTokenCap), and its texts past the short
// path's limit are scored together on the long path before the rest.
func (gw gateway) admitScan(g *textGuard, s scanSizes, forceLarge bool) (scanRun, error) {
	run := scanRun{ctx: gw.base, done: func() {}}
	lim := g.limits
	large := forceLarge || s.untrustedBytes > maxUntrustedBytes || s.historyBytes > maxHistoryBytes ||
		!inference.FitsShort(s.joined)
	for _, t := range s.alone {
		large = large || !inference.FitsShort(t)
	}
	if !large {
		if lim.maxTokens > 0 {
			current := append(append([]string{s.joined}, s.alone...), s.tools...)
			for _, u := range s.untrusted {
				if !u.history {
					current = append(current, u.text)
				}
			}
			ok, err := gw.withinTokens(current, lim.maxTokens)
			if err != nil {
				return run, err
			}
			if !ok {
				return run, errOverTokenCap
			}
		}
		return run, nil
	}
	if !lim.long {
		return run, inference.ErrInputTooLong
	}
	if s.historyBytes > max(maxHistoryBytes, historyBytesPerToken*lim.maxTokens) {
		return run, inference.ErrInputTooLong
	}

	// Admission by size, before any tokenizing.
	release, err := gw.large.acquire(gw.base, g.org)
	if err != nil {
		return run, err
	}
	var short []string
	var long []inference.LongInput
	add := func(text string, threshold float64, history bool, adjust inference.ChunkAdjust) {
		if inference.FitsShort(text) {
			if !history {
				short = append(short, text)
			}
			return
		}
		long = append(long, inference.LongInput{Text: text, Threshold: threshold, Uncounted: history, Adjust: adjust})
	}
	if s.joined != "" {
		add(s.joined, lim.direct, false, nil)
	}
	for _, t := range s.alone {
		add(t, lim.direct, false, nil)
	}
	for _, u := range s.untrusted {
		add(u.text, lim.indirect, u.history, u.adjust)
	}
	short = append(short, s.tools...)
	shortTokens, err := gw.tokensOf(short, lim.maxTokens)
	if err != nil {
		release()
		return run, err
	}
	if shortTokens > lim.maxTokens {
		release()
		return run, errOverTokenCap
	}
	budget := lim.maxTokens - shortTokens
	if budget == 0 {
		budget = -1 // spent
	}
	ls := inference.NewLongScan(inference.LongOptions{Limiter: gw.large.lim, BatchSize: onnx.LongBatchSize(largeBatch), MaxTokens: budget})
	ctx := onnx.WithLimiter(inference.WithLongScan(gw.base, ls), gw.large.lim)
	if err := gw.runner.Prescore(ctx, ls, long); err != nil {
		release()
		observeLong(ls.Stats(), shortTokens)
		if errors.Is(err, inference.ErrInputTooLong) {
			err = errOverTokenCap
		}
		return run, err
	}
	return scanRun{ctx: ctx, large: true, done: func() {
		observeLong(ls.Stats(), shortTokens)
		release()
	}}, nil
}

// observeLong records a large request's long-path work.
func observeLong(st inference.LongStats, shortTokens int) {
	metrics.ScanWindows.WithLabelValues("scored").Add(float64(st.Scored))
	metrics.ScanWindows.WithLabelValues("duplicate").Add(float64(st.Duplicates))
	metrics.ScanWindows.WithLabelValues("skipped").Add(float64(st.Skipped))
	metrics.ScanTokens.Observe(float64(st.Tokens + shortTokens))
}
