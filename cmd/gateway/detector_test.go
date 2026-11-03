package main

import (
	"context"
	"testing"

	appconfig "github.com/giaplee/guard-spec/internal/config"
	"github.com/giaplee/guard-spec/internal/inference/ml"
	"github.com/google/uuid"
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
