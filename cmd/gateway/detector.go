package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	appconfig "github.com/promptshield/promptshield/internal/config"
	"github.com/promptshield/promptshield/internal/inference/ml"
	"github.com/promptshield/promptshield/internal/onnx"
	"github.com/promptshield/promptshield/internal/tenant"
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

// buildDetector loads the detection layers (DETECTOR_LAYERS, L2_MODEL_DIR,
// L3_MODEL_DIR, ...). A missing model or a binary built without -tags onnx
// leaves that layer out with a warning, and the gateway runs on what loaded
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
