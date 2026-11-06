package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	appconfig "github.com/guard-spec/guard-spec/internal/config"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/onnx"
)

func TestBuildDetectorWithoutModels(t *testing.T) {
	cfg := ml.Config{ModelDir: t.TempDir(), Layers: [3]bool{true, true, true}, Fusion: "logreg"}

	// Missing models: L1 only, with a warning.
	t.Setenv(appconfig.EnvVar, "")
	s, err := buildDetector(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Active != [3]bool{true, false, false} {
		t.Fatalf("active %v", s.Active)
	}
	_ = s.Close()

	// DETECTOR_REQUIRE_ML=true refuses to start outside dev mode...
	cfg.RequireML = true
	if _, err := buildDetector(context.Background(), cfg, nil); err == nil {
		t.Fatal("want an error with DETECTOR_REQUIRE_ML=true and no models")
	}
	// ...and only warns in dev mode.
	t.Setenv(appconfig.EnvVar, "dev")
	s, err = buildDetector(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
}

func TestForOrgScopesScans(t *testing.T) {
	org := uuid.New()
	gw := gateway{base: context.Background()}
	scoped := gw.forOrg(org)
	if got, ok := ml.OrgFrom(scoped.base); !ok || got != org {
		t.Fatalf("org %v %v", got, ok)
	}
	if _, ok := ml.OrgFrom(gw.base); ok {
		t.Fatal("forOrg must not change the shared gateway")
	}
	if _, ok := ml.OrgFrom(gw.forOrg(uuid.Nil).base); ok {
		t.Fatal("no org: no scope")
	}
}

func TestReadyzReportsLayers(t *testing.T) {
	runner, err := inference.NewRunner("")
	if err != nil {
		t.Fatal(err)
	}
	gw := testGateway(t, runner)
	gw.detector = newDetectorStatus(&ml.Stack{
		Active:   [3]bool{true, false, true},
		Problems: []string{"l2: no model"},
		Fusion:   "logreg",
	}, false)
	// No API key: /readyz is open, like /health.
	resp, err := newApp(gw, testLookup).Test(httptest.NewRequest("GET", "/readyz", nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Status   string         `json:"status"`
		Detector detectorStatus `json:"detector"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(out.Detector.Layers, ","); got != "l1,l3" {
		t.Errorf("layers = %q, want l1,l3", got)
	}
	if !out.Detector.Degraded || len(out.Detector.Problems) != 1 || out.Detector.Fusion != "logreg" {
		t.Errorf("detector = %+v", out.Detector)
	}
	if out.Detector.ONNX != onnx.Available() {
		t.Errorf("onnx = %v, want %v", out.Detector.ONNX, onnx.Available())
	}
}

func TestDetectorStatusNil(t *testing.T) {
	st := newDetectorStatus(nil, false)
	if st.Layers == nil || len(st.Layers) != 0 {
		t.Errorf("layers = %#v, want empty non-nil", st.Layers)
	}
}

// /readyz answers 503 only when a layer the configuration requires is
// missing; a gateway that runs on fewer layers by design stays ready.
func TestReadyzStatusCode(t *testing.T) {
	runner, err := inference.NewRunner("")
	if err != nil {
		t.Fatal(err)
	}
	full := &ml.Stack{Active: [3]bool{true, true, true}, Fusion: "logreg"}
	l1Only := &ml.Stack{Active: [3]bool{true, false, false}, Problems: []string{"l2: no model", "l3: no model"}}
	for _, tc := range []struct {
		name       string
		stack      *ml.Stack
		required   bool
		wantCode   int
		wantStatus string
	}{
		{"all layers", full, false, 200, "ready"},
		{"all layers, required", full, true, 200, "ready"},
		{"degraded, not required (plain image without models)", l1Only, false, 200, "ready"},
		{"degraded, required (DETECTOR_REQUIRE_ML=true in dev mode)", l1Only, true, 503, "degraded"},
		{"L1 only requested, required", &ml.Stack{Active: [3]bool{true, false, false}}, true, 200, "ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := testGateway(t, runner)
			gw.detector = newDetectorStatus(tc.stack, tc.required)
			resp, err := newApp(gw, testLookup).Test(httptest.NewRequest("GET", "/readyz", nil), -1)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.wantCode {
				t.Fatalf("status code = %d, want %d", resp.StatusCode, tc.wantCode)
			}
			var out struct {
				Status   string         `json:"status"`
				Detector detectorStatus `json:"detector"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			if out.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", out.Status, tc.wantStatus)
			}
			// The body stays detailed whatever the code.
			if out.Detector.Degraded != tc.stack.Degraded() || out.Detector.Required != tc.required ||
				len(out.Detector.Problems) != len(tc.stack.Problems) {
				t.Errorf("detector = %+v", out.Detector)
			}
		})
	}
}
