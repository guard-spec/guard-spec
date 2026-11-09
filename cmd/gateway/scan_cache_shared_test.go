// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeShared is a shared layer in a map, as Redis or Postgres would be.
type fakeShared struct {
	layer string
	now   func() time.Time

	mu      sync.Mutex
	vals    map[string][]byte
	expires map[string]time.Time
	orgs    map[string]uuid.UUID
	ttls    []time.Duration
	gets    atomic.Int64

	err   error // every call fails with it
	block bool  // every call waits for its context
}

func newFakeShared() *fakeShared {
	return &fakeShared{layer: cacheBackendRedis, now: time.Now, vals: map[string][]byte{},
		expires: map[string]time.Time{}, orgs: map[string]uuid.UUID{}}
}

func (m *fakeShared) name() string { return m.layer }

func (m *fakeShared) fail(ctx context.Context) error {
	if m.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return m.err
}

func (m *fakeShared) get(ctx context.Context, org uuid.UUID, keys []string) (map[string][]byte, error) {
	m.gets.Add(1)
	if err := m.fail(ctx); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]byte{}
	for _, k := range keys {
		if v, ok := m.vals[k]; ok && m.orgs[k] == org && m.now().Before(m.expires[k]) {
			out[k] = v
		}
	}
	return out, nil
}

func (m *fakeShared) set(ctx context.Context, org uuid.UUID, entries map[string][]byte, ttl time.Duration) error {
	if err := m.fail(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ttls = append(m.ttls, ttl)
	for k, v := range entries {
		m.vals[k], m.expires[k], m.orgs[k] = v, m.now().Add(ttl), org
	}
	return nil
}

func (m *fakeShared) close() error { return nil }

// values returns every stored value.
func (m *fakeShared) values() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out [][]byte
	for _, v := range m.vals {
		out = append(out, v)
	}
	return out
}

func fixedIdentity(id string) func() (string, bool) {
	return func() (string, bool) { return id, true }
}

// sharedCache is an in-process cache in front of store.
func sharedCache(store sharedStore, identity string, timeout time.Duration) *scanCache {
	c := newScanCache(defaultScanCacheSize, scanCacheTTL)
	c.shared, c.timeout, c.identity = store, timeout, fixedIdentity(identity)
	return c
}

func TestSharedKey(t *testing.T) {
	org := uuid.New()
	k := cacheKey(org, cacheSource, "tool", "output")
	if sharedKey("m1", k) == sharedKey("m2", k) || sharedKey("m1", k) == sharedKey("m1", cacheKey(uuid.New(), cacheSource, "tool", "output")) {
		t.Error("shared keys collide")
	}
	if first, again := sharedKey("m1", k), sharedKey("m1", k); first != again || len(first) != 64 {
		t.Error("shared key not a stable SHA-256")
	}
	if sharedKey("m", "1"+k) == sharedKey("m1", k) {
		t.Error("identity and key run into each other")
	}
}

func TestSharedValueRoundTrip(t *testing.T) {
	scores := inference.Scores{
		Injection: inference.Score{Label: "direct_injection", Confidence: 0.8125, Detail: &inference.Detail{
			L1: 0.1, L2: 0.9, L3: 1.0 / 3, Category: "direct_injection",
			Categories: map[string]float64{"direct_injection": 0.9}, Rules: []string{"ignore-previous"}}},
		PII:      []inference.PIIEntity{{Type: "EMAIL", Start: 3, End: 20, Score: 0.99}},
		Toxicity: inference.Score{Label: "nontoxic", Confidence: 0.01},
	}
	verdict := indirect.Verdict{Source: indirect.SourceTool, Score: 0.91, Category: "indirect_injection",
		DetectorCategory: "direct_injection", Rules: []string{"r1"}, Signals: []string{"<important>"}, Scores: scores}
	for _, tt := range []struct {
		kind string
		in   any
		want any
	}{
		{cacheDirect, scores, scores},
		{cacheSource, verdict, verdict},
		{cacheTool, indirect.ToolVerdict{Name: "secret_tool_name", Verdict: verdict}, indirect.ToolVerdict{Verdict: verdict}},
	} {
		b, err := encodeShared("model-a", tt.kind, tt.in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "secret_tool_name") {
			t.Errorf("%s: tool name stored: %s", tt.kind, b)
		}
		got, err := decodeShared("model-a", tt.kind, b)
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: round trip\n got %#v %v\nwant %#v", tt.kind, got, err, tt.want)
		}
		if _, err := decodeShared("model-b", tt.kind, b); err == nil {
			t.Errorf("%s: read under another model identity", tt.kind)
		}
		other := cacheDirect
		if tt.kind == cacheDirect {
			other = cacheSource
		}
		if _, err := decodeShared("model-a", other, b); err == nil {
			t.Errorf("%s: read as %s", tt.kind, other)
		}
	}
	if _, err := encodeShared("m", cacheDirect, 42); err == nil {
		t.Error("encoded an unknown value type")
	}
	if _, err := decodeShared("m", cacheDirect, []byte("not json")); err == nil {
		t.Error("decoded garbage")
	}
}

// A new model identity is a miss: replicas with other models never share
// entries, and a reload needs no flush.
func TestSharedCacheModelIdentity(t *testing.T) {
	store := newFakeShared()
	org := uuid.New()
	key := cacheKey(org, cacheDirect, "system", "You are a coding agent.")
	req := []cacheReq{{cacheDirect, key}}
	val := inference.Scores{Injection: inference.Score{Label: "BENIGN", Confidence: 0.02}}

	a := sharedCache(store, "model-1", time.Second)
	v := a.view(context.Background(), 1, org, req)
	if _, ok := v.get(key); ok {
		t.Fatal("hit in an empty cache")
	}
	v.put(cacheDirect, key, val)
	v.flush(context.Background())
	if len(store.ttls) != 1 || store.ttls[0] != scanCacheTTL {
		t.Fatalf("ttl %v, want %v", store.ttls, scanCacheTTL)
	}

	// Another replica, same models: a shared hit, copied into its own layer.
	b := sharedCache(store, "model-1", time.Second)
	if got, ok := b.view(context.Background(), 1, org, req).get(key); !ok || !reflect.DeepEqual(got, val) {
		t.Fatalf("other replica: %v %v", got, ok)
	}
	gets := store.gets.Load()
	if _, ok := b.view(context.Background(), 1, org, req).get(key); !ok || store.gets.Load() != gets {
		t.Error("an in-process hit went to the shared layer")
	}
	// Another org with the same text: a miss.
	if _, ok := sharedCache(store, "model-1", time.Second).view(context.Background(), 1, uuid.New(),
		[]cacheReq{{cacheDirect, cacheKey(uuid.New(), cacheDirect, "system", "You are a coding agent.")}}).get(key); ok {
		t.Error("another org hit")
	}
	// Other models (a replica not upgraded yet, or a reload): a miss.
	if _, ok := sharedCache(store, "model-2", time.Second).view(context.Background(), 1, org, req).get(key); ok {
		t.Error("another model identity hit")
	}
	// The identity not known yet: the shared layer is skipped both ways.
	c := sharedCache(store, "model-1", time.Second)
	c.identity = func() (string, bool) { return "", false }
	gets = store.gets.Load()
	v = c.view(context.Background(), 1, org, req)
	if _, ok := v.get(key); ok || store.gets.Load() != gets {
		t.Error("shared layer read without an identity")
	}
	v.put(cacheDirect, key, val)
	v.flush(context.Background())
	if len(store.ttls) != 1 {
		t.Error("shared layer written without an identity")
	}
	// The models changed while the request was scanned: not written.
	id := "model-1"
	d := sharedCache(store, "", time.Second)
	d.identity = func() (string, bool) { return id, true }
	v = d.view(context.Background(), 1, org, []cacheReq{{cacheDirect, "k2"}})
	v.put(cacheDirect, "k2", val)
	id = "model-2"
	v.flush(context.Background())
	if len(store.ttls) != 1 {
		t.Error("written under a stale identity")
	}
	// The TTL holds in the shared layer too.
	store.now = func() time.Time { return time.Now().Add(scanCacheTTL + time.Minute) }
	if _, ok := sharedCache(store, "model-1", time.Second).view(context.Background(), 1, org, req).get(key); ok {
		t.Error("expired shared entry returned")
	}
}

// A failing or slow shared layer costs at most the timeout: the request is
// scanned and answered as without it.
func TestSharedCacheFallback(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
	})
	for _, tt := range []struct {
		name  string
		store *fakeShared
	}{
		{"error", &fakeShared{layer: cacheBackendRedis, err: errors.New("connection refused")}},
		{"timeout", &fakeShared{layer: cacheBackendPostgres, block: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			getErrs := testutil.ToFloat64(metrics.ScanCacheErrors.WithLabelValues(tt.store.layer, "get"))
			setErrs := testutil.ToFloat64(metrics.ScanCacheErrors.WithLabelValues(tt.store.layer, "set"))
			var counter *countingBackend
			h := startGateway(t, "", func(gw *gateway) {
				withAnthropic(up.URL)(gw)
				withCountingRunner(t, &counter)(gw)
				gw.cache = sharedCache(tt.store, "m", 50*time.Millisecond)
			})
			outputs := []string{"build ok", "tests ok"}
			start := time.Now()
			resp, got := h.post(t, "/v1/messages", sessionBody(outputs, ""), nil)
			if resp.StatusCode != 200 {
				t.Fatalf("%d %s", resp.StatusCode, got)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("took %v", d)
			}
			if counter.runs.Load() == 0 {
				t.Error("nothing scanned")
			}
			// An attack is still refused: a broken cache never skips scanning.
			resp, got = h.post(t, "/v1/messages", sessionBody([]string{toolAttack}, ""), nil)
			assertAnthropicError(t, resp, got, 400, "invalid_request_error")
			if d := testutil.ToFloat64(metrics.ScanCacheErrors.WithLabelValues(tt.store.layer, "get")) - getErrs; d < 2 {
				t.Errorf("get errors counted %v", d)
			}
			if d := testutil.ToFloat64(metrics.ScanCacheErrors.WithLabelValues(tt.store.layer, "set")) - setErrs; d < 2 {
				t.Errorf("set errors counted %v", d)
			}
		})
	}
}

func TestLoadScanCacheConfig(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	cfg, err := loadScanCacheConfig(env())
	if err != nil || cfg.Backend != cacheBackendMemory || cfg.Timeout != defaultScanCacheTimeout {
		t.Errorf("default %+v %v", cfg, err)
	}
	cfg, err = loadScanCacheConfig(env("SCAN_CACHE_BACKEND", "Redis", "SCAN_CACHE_REDIS_URL", "rediss://:pw@cache:6380/1",
		"SCAN_CACHE_TIMEOUT", "20ms"))
	if err != nil || cfg.Backend != cacheBackendRedis || cfg.Timeout != 20*time.Millisecond {
		t.Errorf("redis %+v %v", cfg, err)
	}
	for _, bad := range [][]string{
		{"SCAN_CACHE_BACKEND", "memcached"},
		{"SCAN_CACHE_BACKEND", "redis"},
		{"SCAN_CACHE_BACKEND", "redis", "SCAN_CACHE_REDIS_URL", "http://:hunter2-secret@cache"},
		{"SCAN_CACHE_BACKEND", "postgres", "SCAN_CACHE_TIMEOUT", "0s"},
		{"SCAN_CACHE_TIMEOUT", "1h"},
	} {
		_, err := loadScanCacheConfig(env(bad...))
		if err == nil {
			t.Errorf("%v accepted", bad)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error shows the password: %v", err)
		}
	}
}

// benignBackend scores every text benign.
type benignBackend struct{}

func (benignBackend) Run(context.Context, string) ([]inference.Score, error) {
	return []inference.Score{{Label: "BENIGN", Confidence: 0.01}}, nil
}

// sessionRun is what runReplicaSession saw.
type sessionRun struct {
	status  []int   // per turn, alternating replicas a and b
	scanned []int64 // detector bytes per turn
	// restarted is the status of the next turn sent to a restarted b, with
	// the bytes it scanned.
	restarted        int
	restartedScanned int64
	historyBytes     int
}

// runReplicaSession plays a long Claude Code session against two gateway
// replicas, a and b, each with its own in-process cache in front of the
// shared layer newStore returns (nil: memory only). Turns alternate between
// them, as behind a load balancer; each turn adds a tool output of
// sessionChunk bytes, and the session ends with more than maxHistoryBytes of
// tool output, far past maxUntrustedBytes (128 KiB). Then b restarts (a new
// process: an empty in-process cache) and gets the next turn.
func runReplicaSession(t *testing.T, newStore func() sharedStore, turns int) sessionRun {
	t.Helper()
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
	})
	replica := func() (*harness, *countingBackend) {
		// A detector that finds nothing, quickly: what is scanned is
		// counted, not judged, so the test does not run L1 over megabytes.
		counter := &countingBackend{inner: benignBackend{}}
		h := startGateway(t, "", func(gw *gateway) {
			withAnthropic(up.URL)(gw)
			gw.runner = inference.NewRunnerWith(counter)
			gw.cache = newScanCache(defaultScanCacheSize, scanCacheTTL)
			if newStore != nil {
				// Generous: the test machine may be busy; the default is 50ms.
				gw.cache.shared, gw.cache.timeout = newStore(), 2*time.Second
				gw.cache.identity = fixedIdentity("two-replica-test-model")
			}
		})
		return h, counter
	}
	a, ca := replica()
	b, cb := replica()
	var run sessionRun
	var outputs []string
	for turn := range turns {
		// Distinct lines, so that no turn's output is a copy of another's.
		var sb strings.Builder
		for i := 0; sb.Len() < sessionChunk; i++ {
			fmt.Fprintf(&sb, "turn %d line %d: src/pkg/file_%d.go:%d: func handler() error { return nil } ZQX-MARKER-7731\n", turn, i, turn, i)
		}
		outputs = append(outputs, sb.String())
		run.historyBytes += sb.Len()
		h, c := a, ca
		if turn%2 == 1 {
			h, c = b, cb
		}
		before := c.bytes.Load()
		resp, got := h.post(t, "/v1/messages", sessionBody(outputs, ""), nil)
		if resp.StatusCode != 200 {
			t.Logf("turn %d: %d %s", turn, resp.StatusCode, got)
		}
		run.status = append(run.status, resp.StatusCode)
		run.scanned = append(run.scanned, c.bytes.Load()-before)
	}
	b2, cb2 := replica() // b restarted
	resp, got := b2.post(t, "/v1/messages", sessionBody(outputs, "and now?"), nil)
	if resp.StatusCode != 200 {
		t.Logf("after restart: %d %.200s", resp.StatusCode, got)
	}
	run.restarted, run.restartedScanned = resp.StatusCode, cb2.bytes.Load()
	return run
}

// Each turn adds a tool output of sessionChunk bytes (within
// maxUntrustedBytes); sessionTurns of them pass maxHistoryBytes.
const (
	sessionChunk = 64 << 10
	sessionTurns = 17
)

// checkSharedSession asserts what a shared layer should achieve.
func checkSharedSession(t *testing.T, run sessionRun) {
	t.Helper()
	if run.historyBytes <= maxHistoryBytes {
		t.Fatalf("session too short: %d bytes", run.historyBytes)
	}
	for turn, s := range run.status {
		if s != 200 {
			t.Errorf("turn %d on replica %c: %d", turn, "ab"[turn%2], s)
		}
		// Only the new output (and the short trailing texts): every earlier
		// one is in the shared layer, whichever replica scored it.
		if run.scanned[turn] > sessionChunk*5/4 {
			t.Errorf("turn %d scanned %d bytes", turn, run.scanned[turn])
		}
	}
	if run.restarted != 200 || run.restartedScanned > 4<<10 {
		t.Errorf("after restart: %d, scanned %d bytes", run.restarted, run.restartedScanned)
	}
	t.Logf("shared: %d turns, %d KiB of tool output; max scanned per turn %d KiB; after restart %d, scanned %d bytes",
		len(run.status), run.historyBytes>>10, maxOf(run.scanned)>>10, run.restarted, run.restartedScanned)
}

func maxOf(xs []int64) int64 {
	var m int64
	for _, x := range xs {
		m = max(m, x)
	}
	return m
}

// assertNoText fails when a stored value holds any text of the session.
func assertNoText(t *testing.T, values [][]byte) {
	t.Helper()
	if len(values) == 0 {
		t.Fatal("nothing stored")
	}
	for _, v := range values {
		for _, text := range []string{"ZQX-MARKER-7731", "func handler", "first question", "You are a coding agent",
			"Runs a command", "Bash", "claude-x", "and now?"} {
			if strings.Contains(string(v), text) {
				t.Fatalf("stored value holds %q: %s", text, v)
			}
		}
	}
}

// Two replicas on one shared layer keep a long session going, alternating
// and after a restart; with memory only the restarted replica refuses it.
func TestTwoReplicasSharedCache(t *testing.T) {
	store := newFakeShared()
	run := runReplicaSession(t, func() sharedStore { return store }, sessionTurns)
	checkSharedSession(t, run)
	assertNoText(t, store.values())
	if len(store.ttls) == 0 || store.ttls[0] != scanCacheTTL {
		t.Errorf("ttl %v", store.ttls)
	}

	mem := runReplicaSession(t, nil, sessionTurns)
	checkMemorySession(t, mem)
}

// checkMemorySession asserts the behaviour without a shared layer: each
// replica rescans what the other scored, and a restarted replica has to scan
// the whole history, which is over maxHistoryBytes: 413.
func checkMemorySession(t *testing.T, run sessionRun) {
	t.Helper()
	if run.restarted != 413 {
		t.Errorf("memory only, after restart: %d, want 413", run.restarted)
	}
	// Each replica scans the output the other one scored last turn again.
	if last := run.scanned[len(run.scanned)-1]; last < sessionChunk*7/4 {
		t.Errorf("memory only, last turn scanned %d bytes, want two outputs", last)
	}
	t.Logf("memory: %d turns, statuses ok until turn %d; max scanned per turn %d KiB; after restart %d",
		len(run.status), firstNot200(run.status), maxOf(run.scanned)>>10, run.restarted)
}

func firstNot200(s []int) int {
	for i, x := range s {
		if x != 200 {
			return i
		}
	}
	return len(s)
}

// /v1/responses goes through the same cache view: a turn on another replica
// takes the earlier tool outputs from the shared layer.
func TestResponsesSharedCacheAcrossReplicas(t *testing.T) {
	up := newFakeUpstream(t, func(w http.ResponseWriter, _ *http.Request) { responseJSON(w, responseObject(textItem("ok"))) })
	store := newFakeShared()
	replica := func() (*harness, *countingBackend) {
		counter := &countingBackend{inner: benignBackend{}}
		h := startGateway(t, up.URL, func(gw *gateway) {
			gw.runner = inference.NewRunnerWith(counter)
			gw.cache = sharedCache(store, "responses-model", 2*time.Second)
		})
		return h, counter
	}
	a, _ := replica()
	b, cb := replica()
	out1 := strings.Repeat("first tool output line ZQX-MARKER-7731\n", 400)
	// Numbered lines: the runner scores identical chunks once, so a text
	// that repeats would count fewer bytes than its length.
	var b2 strings.Builder
	for i := range 400 {
		fmt.Fprintf(&b2, "second tool output line %03d\n", i)
	}
	out2 := b2.String()
	item := func(id, out string) string {
		return `{"type":"function_call","call_id":"` + id + `","name":"w","arguments":"{}"},
			{"type":"function_call_output","call_id":"` + id + `","output":` + jsonQuote(out) + `}`
	}
	turn1 := `{"model":"m","instructions":"You are a coding agent.","input":[{"role":"user","content":"weather?"},` +
		item("c1", out1) + `]}`
	turn2 := `{"model":"m","instructions":"You are a coding agent.","input":[{"role":"user","content":"weather?"},` +
		item("c1", out1) + `,` + item("c2", out2) + `]}`
	if resp, got := a.post(t, "/v1/responses", turn1, nil); resp.StatusCode != 200 {
		t.Fatalf("turn 1 on a: %d %s", resp.StatusCode, got)
	}
	if resp, got := b.post(t, "/v1/responses", turn2, nil); resp.StatusCode != 200 {
		t.Fatalf("turn 2 on b: %d %s", resp.StatusCode, got)
	}
	// b scanned the new output (and short direct text), not the first one.
	if scanned := cb.bytes.Load(); scanned >= int64(len(out1)+len(out2)) || scanned < int64(len(out2)) {
		t.Errorf("b scanned %d bytes; outputs are %d and %d", scanned, len(out1), len(out2))
	}
	assertNoText(t, store.values())
}
