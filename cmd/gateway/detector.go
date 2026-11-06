package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	appconfig "github.com/guard-spec/guard-spec/internal/config"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/onnx"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxOrgExemplars bounds what the gateway loads and embeds for one org; the
// control plane refuses to store more.
const maxOrgExemplars = 1000

// forOrg scopes the scans of one request to its organization, so that L3
// uses the org's own exemplars.
func (gw gateway) forOrg(org uuid.UUID) gateway {
	gw.base = ml.WithOrg(gw.base, org)
	return gw
}

// buildDetector loads the detection layers (DETECTOR_LAYERS, L2_MODEL,
// L2_MODEL_DIR, L3_MODEL, L3_MODEL_DIR, ...; ml.ResolveL2Dir gives the order).
// A missing model or a binary built without -tags onnx leaves that layer out
// with a warning, and the gateway runs on what loaded
// (L1 at least); scores.l2 / scores.l3 are then -1. Outside GUARD_ENV=dev,
// DETECTOR_REQUIRE_ML=true makes that fatal.
func buildDetector(ctx context.Context, cfg ml.Config, store ml.TenantStore) (*ml.Stack, error) {
	stack, err := ml.Build(ctx, cfg, store)
	if err != nil {
		return nil, err
	}
	if stack.Degraded() {
		for _, p := range stack.Problems {
			slog.Warn("detection layer unavailable; running without it", "problem", p, "onnx_compiled_in", onnx.Available())
		}
		if cfg.RequireML {
			if !appconfig.DevMode() {
				_ = stack.Close()
				return nil, fmt.Errorf("%s=true and model layers are missing: %s", ml.EnvRequireML, strings.Join(stack.Problems, "; "))
			}
			slog.Warn(ml.EnvRequireML + "=true is not enforced with GUARD_ENV=dev")
		}
	}
	casc := "off"
	if cfg.Cascade != nil {
		casc = fmt.Sprintf("low=%.4g high=%.4g", cfg.Cascade.Low, cfg.Cascade.High)
	}
	slog.Info("detector", "layers", ml.LayerKey(stack.Active), "fusion", stack.Fusion, "cascade", casc, "l2_model", stack.L2Model)
	return stack, nil
}

// dbExemplarStore reads org_exemplars (migration 009) in the org's RLS scope.
type dbExemplarStore struct{ db *pgxpool.Pool }

func (s dbExemplarStore) ExemplarVersion(ctx context.Context, org uuid.UUID) (int64, error) {
	var v int64
	err := tenant.WithOrg(ctx, s.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT exemplars_version FROM organizations WHERE id = $1`, org).Scan(&v)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

func (s dbExemplarStore) Exemplars(ctx context.Context, org uuid.UUID) ([]ml.Exemplar, error) {
	var out []ml.Exemplar
	err := tenant.WithOrg(ctx, s.db, org, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, label, text, source FROM org_exemplars
			 WHERE org_id = $1 ORDER BY created_at, id LIMIT $2`, org, maxOrgExemplars)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var x ml.Exemplar
			if err := rows.Scan(&id, &x.Label, &x.Text, &x.Source); err != nil {
				return err
			}
			x.ID, x.Category = id.String(), ml.TenantCategory
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// detectorStatus is the detection part of the /readyz response.
type detectorStatus struct {
	// Layers are the active layers, e.g. ["l1"] or ["l1","l2","l3"].
	Layers []string `json:"layers"`
	// Degraded is true when a requested layer did not load; Problems says why.
	Degraded bool     `json:"degraded"`
	Problems []string `json:"problems,omitempty"`
	// Required is DETECTOR_REQUIRE_ML: the requested model layers must load.
	// Outside GUARD_ENV=dev a gateway that is degraded and required does not
	// start at all; in dev mode it starts and /readyz answers 503.
	Required bool `json:"required"`
	// ONNX reports whether the binary was built with -tags onnx.
	ONNX    bool   `json:"onnx"`
	Fusion  string `json:"fusion,omitempty"`
	L2Model string `json:"l2_model,omitempty"`
}

// ready reports whether the gateway may take traffic: a missing layer counts
// only when the configuration requires it (DETECTOR_REQUIRE_ML=true). A
// gateway that runs L1 only by design, such as the plain image without
// models, is degraded but ready.
func (d detectorStatus) ready() bool { return !(d.Degraded && d.Required) }

// newDetectorStatus describes the loaded stack; required is cfg.RequireML.
func newDetectorStatus(s *ml.Stack, required bool) detectorStatus {
	st := detectorStatus{Layers: []string{}, ONNX: onnx.Available(), Required: required}
	if s == nil {
		return st
	}
	if k := ml.LayerKey(s.Active); k != "" {
		st.Layers = strings.Split(k, ",")
	}
	st.Degraded, st.Problems = s.Degraded(), s.Problems
	st.Fusion, st.L2Model = s.Fusion, s.L2Model
	return st
}
