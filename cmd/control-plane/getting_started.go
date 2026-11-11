// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The getting started checklist of the admin UI (RF-a1dbafea U1):
//
//	GET /organizations/:orgId/getting-started
//
// One answer with the state of each setup step, counts only, so that a
// viewer sees the same checklist as an admin (a viewer cannot list the API
// keys, for instance, but may know that one exists). The required steps are
// a model provider, an API key, an enabled policy and the gateway's
// detection layers; an alert channel and the input settings are recommended.
// complete is true once the required steps are done.

// startWindow is how far back the request log tells whether the upstream answers.
const startWindow = 7 * 24 * time.Hour

type startUpstream struct {
	// Configured: an enabled named upstream, or the gateway's UPSTREAM_LLM_URL.
	Configured bool `json:"configured"`
	Upstreams  int  `json:"upstreams"`
	Env        bool `json:"env"`
	// Reachable is read from the request log of the last 7 days: true when
	// the latest forwarded request got an answer, false when it failed
	// (action error), null without traffic.
	Reachable    *bool      `json:"reachable"`
	LastAnswerAt *time.Time `json:"last_answer_at"`
	LastErrorAt  *time.Time `json:"last_error_at"`
}

type startModels struct {
	// Configured: the control plane has GATEWAY_URL.
	Configured bool     `json:"configured"`
	Reachable  bool     `json:"reachable"`
	Layers     []string `json:"layers"`
	Version    string   `json:"version,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type gettingStarted struct {
	Upstream      startUpstream `json:"upstream"`
	APIKeys       int           `json:"api_keys"`
	Policies      int           `json:"policies"`
	Models        startModels   `json:"models"`
	AlertChannels int           `json:"alert_channels"`
	// InputSettings: the org set its own input settings (else it inherits
	// the instance's behaviour).
	InputSettings bool      `json:"input_settings"`
	Complete      bool      `json:"complete"`
	CheckedAt     time.Time `json:"checked_at"`
}

// startCounts reads the org's part of the checklist in tx.
func startCounts(ctx context.Context, tx pgx.Tx, org uuid.UUID, out *gettingStarted) error {
	since := time.Now().Add(-startWindow)
	return tx.QueryRow(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM upstreams WHERE org_id = $1 AND enabled),
		  (SELECT COUNT(*) FROM api_keys WHERE org_id = $1 AND revoked_at IS NULL
		      AND (expires_at IS NULL OR expires_at > NOW())),
		  (SELECT COUNT(*) FROM policies WHERE org_id = $1 AND enabled),
		  (SELECT COUNT(*) FROM notification_channels WHERE org_id = $1 AND enabled),
		  EXISTS (SELECT 1 FROM org_input_settings WHERE org_id = $1),
		  (SELECT MAX(created_at) FROM requests WHERE org_id = $1 AND created_at >= $2
		      AND action NOT IN ('block', 'error') AND response_sha256 IS NOT NULL),
		  (SELECT MAX(created_at) FROM requests WHERE org_id = $1 AND created_at >= $2 AND action = 'error')`,
		org, since).Scan(&out.Upstream.Upstreams, &out.APIKeys, &out.Policies, &out.AlertChannels, &out.InputSettings,
		&out.Upstream.LastAnswerAt, &out.Upstream.LastErrorAt)
}

// upstreamReachable is the reachability the request log shows: the later of
// the last answer and the last failure decides; nil without either.
func upstreamReachable(answer, failure *time.Time) *bool {
	var ok bool
	switch {
	case answer == nil && failure == nil:
		return nil
	case failure == nil:
		ok = true
	case answer == nil:
		ok = false
	default:
		ok = answer.After(*failure)
	}
	return &ok
}

// startComplete reports whether the required steps are done.
func startComplete(s gettingStarted) bool {
	return s.Upstream.Configured && s.APIKeys > 0 && s.Policies > 0 && s.Models.Reachable && len(s.Models.Layers) > 0
}

func getGettingStarted(db *pgxpool.Pool, settings *appSettings) fiber.Handler {
	client := gatewayStatusClient(settings)
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		out := gettingStarted{CheckedAt: time.Now().UTC()}
		if err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return startCounts(c.Context(), tx, org, &out)
		}); err != nil {
			return serverError(c, err)
		}
		out.Upstream.Env = settings.envUpstreamURL != ""
		out.Upstream.Configured = out.Upstream.Upstreams > 0 || out.Upstream.Env
		out.Upstream.Reachable = upstreamReachable(out.Upstream.LastAnswerAt, out.Upstream.LastErrorAt)

		out.Models.Layers = []string{}
		if settings.gatewayURL != "" {
			out.Models.Configured = true
			st, err := fetchReadyz(c.Context(), client, settings.gatewayURL)
			if err != nil {
				out.Models.Error = err.Error()
			} else {
				out.Models.Reachable, out.Models.Version = true, st.Version
				if st.Detector.Layers != nil {
					out.Models.Layers = st.Detector.Layers
				}
			}
		}
		out.Complete = startComplete(out)
		return c.JSON(out)
	}
}
