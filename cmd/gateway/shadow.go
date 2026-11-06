// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/jackc/pgx/v5"
)

// Shadow mode (internal/inference/ml/shadow.go): a candidate classifier scores
// the same texts as the active one in the background. A request's comparison
// is written with its audit row, in the same transaction, to shadow_results
// (migration 017). It holds scores, model names and the two decisions, never
// any content.

// forRequest scopes the scans of one request to its org and, when shadow mode
// is on and the request is sampled, attaches the request's shadow recorder.
func (gw gateway) forRequest(e *requestEntry) gateway {
	gw = gw.forOrg(e.OrgID)
	if gw.live == nil || !gw.live.ShadowEnabled() {
		return gw
	}
	cfg := gw.live.ShadowConfig()
	if cfg.Sample < 1 && rand.Float64() >= cfg.Sample { //nolint:gosec // sampling, not security
		return gw
	}
	e.Shadow, e.ShadowWait = ml.NewRecorder(), cfg.Timeout
	gw.base = ml.WithRecorder(gw.base, e.Shadow)
	return gw
}

// decision is what the fixed direct threshold makes of a score.
func decision(score float64) string {
	if score >= injectionBlockThreshold {
		return actionBlock
	}
	return actionAllow
}

// shadowRow waits (within the budget) for the request's comparison. ok is
// false when there is nothing to store.
func shadowRow(e requestEntry) (ml.ShadowResult, bool) {
	if e.Shadow == nil {
		return ml.ShadowResult{}, false
	}
	wait := e.ShadowWait
	if wait <= 0 {
		wait = shadowBudget
	}
	res := e.Shadow.Wait(wait)
	return res, res.Status != ""
}

const shadowInsert = `
INSERT INTO shadow_results
	(request_id, org_id, project_id, status, active_model, shadow_model,
	 active_score, shadow_score, active_l2, shadow_l2, active_decision, shadow_decision, texts, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
	COALESCE((SELECT created_at FROM requests WHERE id = $1), NOW()))`

// insertShadow writes the comparison of the request row id. Scores of a side
// that did not finish are NULL, and so are its decisions.
func insertShadow(ctx context.Context, tx pgx.Tx, e requestEntry, res ml.ShadowResult) error {
	score := func(v float64) *float64 {
		if v == fusion.Missing {
			return nil
		}
		return &v
	}
	var activeDec, shadowDec *string
	if res.Status == ml.ShadowOK {
		a, s := decision(res.ActiveScore), decision(res.ShadowScore)
		activeDec, shadowDec = &a, &s
	}
	shadowScore, shadowL2 := score(res.ShadowScore), score(res.ShadowL2)
	if res.Status != ml.ShadowOK {
		shadowScore, shadowL2 = nil, nil // partial: not comparable
	}
	_, err := tx.Exec(ctx, shadowInsert, e.ID, e.OrgID, nullUUID(e.ProjectID), res.Status,
		nonEmpty(res.ActiveModel), nonEmpty(res.ShadowModel), score(res.ActiveScore), shadowScore,
		score(res.ActiveL2), shadowL2, activeDec, shadowDec, res.Texts)
	return err
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// shadowBudget bounds how long the audit writer waits for a comparison when
// no timeout was set (tests).
const shadowBudget = 2 * time.Second
