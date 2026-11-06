// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

// fakeClassifier stands in for an ONNX classifier: a fixed risk per version,
// and an error once closed.
type fakeClassifier struct {
	risk   float32
	delay  time.Duration
	closed atomic.Bool
}

func (c *fakeClassifier) Score(ctx context.Context, _ []string) ([][]float32, error) {
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.closed.Load() {
		return nil, onnx.ErrClosed
	}
	return [][]float32{{1 - c.risk, c.risk}}, nil
}
func (*fakeClassifier) Labels() []string { return []string{"benign", "direct_injection"} }
func (*fakeClassifier) BenignIndex() int { return 0 }
func (c *fakeClassifier) Close() error {
	c.closed.Store(true)
	return nil
}

const testAdminToken = "test-admin-token-0123456789abcdef0123456789"

// modelTestGateway is a gateway whose L2 classifier is a fake loaded from a
// MODEL_DIR with versions v2 (risk 0.95) and v3b (risk 0.1, recommended)
// pinned by a manifest file. It starts on v3b, with shadow on v2 when shadow
// is set. Audit rows go to rows.
func modelTestGateway(t *testing.T, shadow bool, delay time.Duration, rows chan<- requestEntry) (gateway, string) {
	t.Helper()
	dir := t.TempDir()
	risks := map[string]float32{"v2": 0.95, "v3b": 0.1}
	var manifest strings.Builder
	manifest.WriteString("models:\n")
	for v := range risks {
		d := filepath.Join(dir, ml.ModelCacheSubdir, "guardspec-classifier", v)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "  - name: guardspec-classifier\n    version: %s\n    kind: classifier\n    recommended: %v\n"+
			"    repo: guard-spec/guardspec-classifier\n    revision: %s\n    license: Apache-2.0\n    files:\n",
			v, v == "v3b", strings.Repeat("b", 40))
		for _, name := range []string{onnx.ConfigFile, "model.onnx"} {
			content := name + " of " + v
			if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(content))
			fmt.Fprintf(&manifest, "      - src: %s\n        dest: %s\n        sha256: %s\n", name, name, hex.EncodeToString(sum[:]))
		}
	}
	mpath := filepath.Join(dir, "manifest.yaml")
	if err := os.WriteFile(mpath, []byte(manifest.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := ml.Config{ModelDir: dir, Manifest: mpath, Layers: [3]bool{true, true, false}, Fusion: "max",
		L2Model: "guardspec-classifier@v3b"}
	if shadow {
		cfg.Shadow = ml.ShadowConfig{Model: "guardspec-classifier@v2", Timeout: time.Second, Sample: 1, MaxInFlight: 64}
	}
	stack, err := ml.Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	live := ml.NewLiveWithLoader(stack, func(d string, _ onnx.Options) (*ml.L2Model, error) {
		c := &fakeClassifier{risk: risks[filepath.Base(d)], delay: delay}
		return ml.NewL2Model(d, c, c)
	})
	t.Cleanup(func() { _ = live.Close() })
	if _, err := live.Reload(context.Background(), ml.ReloadRequest{}); err != nil {
		t.Fatal(err)
	}
	gw := testGateway(t, inference.NewRunnerWith(inference.FusedBackend{F: live}))
	gw.live, gw.adminToken = live, testAdminToken
	gw.detector = newLiveStatus(stack, live, false)
	if rows != nil {
		gw.audit = newAuditLog(func(e requestEntry) { rows <- e })
	}
	return gw, dir
}

func adminRequest(t *testing.T, app *fiber.App, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/admin/models/reload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func readyzModels(t *testing.T, app *fiber.App) ml.Status {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", "/readyz", nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Detector detectorStatus `json:"detector"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Detector.Models == nil {
		t.Fatal("/readyz has no detector.models")
	}
	return *out.Detector.Models
}

func TestAdminReloadAuth(t *testing.T) {
	gw, _ := modelTestGateway(t, false, 0, nil)
	app := newApp(gw, testLookup)
	if code, _ := adminRequest(t, app, "", ""); code != fiber.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := adminRequest(t, app, "wrong", ""); code != fiber.StatusUnauthorized {
		t.Errorf("wrong token: %d", code)
	}
	// An API key is not an admin token.
	req := httptest.NewRequest("POST", "/admin/models/reload", nil)
	req.Header.Set("x-api-key", "test")
	if resp, err := app.Test(req, -1); err != nil || resp.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("api key: %v %v", resp.StatusCode, err)
	}
	// Without GATEWAY_ADMIN_TOKEN the routes do not exist.
	gw.adminToken = ""
	if code, _ := adminRequest(t, newApp(gw, testLookup), testAdminToken, ""); code != fiber.StatusNotFound {
		t.Errorf("admin off: %d", code)
	}
}

func TestAdminReloadSwitchesAndReports(t *testing.T) {
	gw, dir := modelTestGateway(t, false, 0, nil)
	app := newApp(gw, testLookup)
	if st := readyzModels(t, app); st.L2Model != "guardspec-classifier@v3b" || !st.L2Verified || st.UpdateAvailable {
		t.Fatalf("start: %+v", st)
	}
	code, out := adminRequest(t, app, testAdminToken, `{"l2_model":"guardspec-classifier@v2"}`)
	if code != 200 {
		t.Fatalf("reload: %d %v", code, out)
	}
	st := readyzModels(t, app)
	if st.L2Model != "guardspec-classifier@v2" || !st.UpdateAvailable || st.Recommended != "guardspec-classifier@v3b" ||
		st.Reload.At == nil || st.Generation != 2 {
		t.Fatalf("after reload: %+v", st)
	}

	// A tampered file: 409, the running model stays and /readyz says why.
	if err := os.WriteFile(filepath.Join(dir, ml.ModelCacheSubdir, "guardspec-classifier", "v3b", "model.onnx"),
		[]byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out = adminRequest(t, app, testAdminToken, `{"l2_model":"guardspec-classifier@v3b"}`)
	if code != fiber.StatusConflict {
		t.Fatalf("tampered reload: %d %v", code, out)
	}
	st = readyzModels(t, app)
	if st.L2Model != "guardspec-classifier@v2" || st.Generation != 2 || !strings.Contains(st.Reload.Error, "digest") {
		t.Fatalf("after failed reload: %+v", st)
	}
	if code, _ := adminRequest(t, app, testAdminToken, `{not json`); code != fiber.StatusBadRequest {
		t.Fatalf("bad body: %d", code)
	}
}

// TestReloadDoesNotDropRequests sends scans from many clients while the
// classifier is reloaded back and forth over the admin endpoint: every scan
// answers 200 with an L2 score from one of the two versions (run with -race).
func TestReloadDoesNotDropRequests(t *testing.T) {
	gw, _ := modelTestGateway(t, false, 300*time.Microsecond, nil)
	app := newApp(gw, testLookup)
	ctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var served, failed atomic.Int64
	var firstFailure atomic.Value
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				req := httptest.NewRequest("POST", "/guardrail/scan",
					strings.NewReader(`{"text":"Please summarize the attached quarterly report."}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("x-api-key", "test")
				resp, err := app.Test(req, -1)
				if err != nil {
					failed.Add(1)
					firstFailure.CompareAndSwap(nil, err.Error())
					continue
				}
				var out struct {
					Score float64 `json:"injection_score"`
				}
				err = json.NewDecoder(resp.Body).Decode(&out)
				_ = resp.Body.Close()
				served.Add(1)
				// Fusion is max of L1 and L2: v3b gives 0.1, v2 0.95; L1 is
				// low for this text, so the score is one of the two.
				if resp.StatusCode != 200 || err != nil || (abs(out.Score-0.1) > 1e-3 && abs(out.Score-0.95) > 1e-3) {
					failed.Add(1)
					firstFailure.CompareAndSwap(nil, fmt.Sprintf("status %d score %v err %v", resp.StatusCode, out.Score, err))
				}
			}
		}()
	}
	for i := range 10 {
		v := []string{"v2", "v3b"}[i%2]
		if code, out := adminRequest(t, app, testAdminToken, `{"l2_model":"guardspec-classifier@`+v+`"}`); code != 200 {
			t.Errorf("reload %d: %d %v", i, code, out)
		}
	}
	stop()
	wg.Wait()
	if failed.Load() > 0 || served.Load() == 0 {
		t.Fatalf("%d of %d scans failed during reloads (first: %v)", failed.Load(), served.Load(), firstFailure.Load())
	}
	t.Logf("%d scans answered during 10 reloads", served.Load())
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// The shadow candidate's verdict goes to the audit entry, never to the
// response.
func TestShadowRecordedWithAuditEntry(t *testing.T) {
	rows := make(chan requestEntry, 4)
	gw, _ := modelTestGateway(t, true, 0, rows)
	app := newApp(gw, testLookup)
	req := httptest.NewRequest("POST", "/guardrail/scan",
		strings.NewReader(`{"text":"Please summarize the attached quarterly report."}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Score   float64 `json:"injection_score"`
		Blocked bool    `json:"blocked"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || out.Blocked || abs(out.Score-0.1) > 1e-3 {
		t.Fatalf("response %d %+v: the shadow must not change it", resp.StatusCode, out)
	}
	e := <-rows
	res, ok := shadowRow(e)
	if !ok || res.Status != ml.ShadowOK || res.ActiveModel != "guardspec-classifier@v3b" ||
		res.ShadowModel != "guardspec-classifier@v2" || decision(res.ActiveScore) != actionAllow ||
		decision(res.ShadowScore) != actionBlock {
		t.Fatalf("shadow %+v (ok %v)", res, ok)
	}
	if st := readyzModels(t, app); !st.Shadow.Enabled || st.Shadow.Model != "guardspec-classifier@v2" {
		t.Fatalf("readyz shadow %+v", st.Shadow)
	}
}
