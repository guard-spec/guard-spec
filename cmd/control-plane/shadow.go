// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Shadow mode comparison (migration 017): the gateway writes one
// shadow_results row per sampled request when SHADOW_L2_MODEL is set. These
// handlers aggregate them over a window (viewer, like the dashboard) and list
// the requests where the two models disagree (admin). Neither reads any
// request content.

// shadowThreshold is the gateway's direct block threshold, which both
// decisions in shadow_results use.
const shadowThreshold = 0.85

// shadowHistogramBins splits [0, 1] into equal score bins.
const shadowHistogramBins = 10

type shadowScoreStats struct {
	Mean *float64 `json:"mean"`
	P50  *float64 `json:"p50"`
	P95  *float64 `json:"p95"`
}

type shadowDelta struct {
	Mean    *float64 `json:"mean"`
	MeanAbs *float64 `json:"mean_abs"`
	P95Abs  *float64 `json:"p95_abs"`
}

type shadowBin struct {
	From   float64 `json:"from"`
	To     float64 `json:"to"`
	Active int64   `json:"active"`
	Shadow int64   `json:"shadow"`
}

type shadowPair struct {
	ActiveModel string `json:"active_model"`
	ShadowModel string `json:"shadow_model"`
	Count       int64  `json:"count"`
}

type shadowSummary struct {
	Window        string           `json:"window"`
	From          time.Time        `json:"from"`
	To            time.Time        `json:"to"`
	ProjectID     *uuid.UUID       `json:"project_id"`
	Threshold     float64          `json:"threshold"`
	Total         int64            `json:"total"`
	Compared      int64            `json:"compared"`
	Agree         int64            `json:"agree"`
	AgreementRate *float64         `json:"agreement_rate"`
	WouldBlock    int64            `json:"shadow_would_block"`
	WouldAllow    int64            `json:"shadow_would_allow"`
	NotCompared   map[string]int64 `json:"not_compared"`
	Pairs         []shadowPair     `json:"pairs"`
	Scores        struct {
		Active    shadowScoreStats `json:"active"`
		Shadow    shadowScoreStats `json:"shadow"`
		Delta     shadowDelta      `json:"delta"`
		Histogram []shadowBin      `json:"histogram"`
	} `json:"scores"`
}

// shadowFilter is the window (and project) of a shadow query: " FROM
// shadow_results s WHERE ..." with its args.
func shadowFilter(c *fiber.Ctx) (window string, from, to time.Time, project *uuid.UUID, filter string, args []any, err error) {
	window, d, _, err := parseDashboardWindow(c.Query("window"))
	if err != nil {
		return
	}
	to = time.Now().UTC()
	from = to.Add(-d)
	args = []any{orgID(c), from, to}
	// The explicit org filter uses the index; row level security is the backstop.
	filter = ` FROM shadow_results s WHERE s.org_id = $1 AND s.created_at >= $2 AND s.created_at < $3`
	if raw := c.Query("project_id"); raw != "" {
		id, perr := uuid.Parse(raw)
		if perr != nil {
			err = errors.New("invalid project_id")
			return
		}
		project = &id
		args = append(args, id)
		filter += fmt.Sprintf(" AND s.project_id = $%d", len(args))
	}
	return
}

func getShadowSummary(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		window, from, to, project, filter, args, err := shadowFilter(c)
		if err != nil {
			return badRequest(c, err.Error())
		}
		s := shadowSummary{Window: window, From: from, To: to, ProjectID: project, Threshold: shadowThreshold}
		err = tenant.WithOrg(c.Context(), db, orgID(c), func(tx pgx.Tx) error {
			return queryShadowSummary(c.Context(), tx, filter, args, &s)
		})
		if err != nil {
			return serverError(c, err)
		}
		if s.Compared > 0 {
			r := float64(s.Agree) / float64(s.Compared)
			s.AgreementRate = &r
		}
		return c.JSON(s)
	}
}

func queryShadowSummary(ctx context.Context, tx pgx.Tx, filter string, args []any, s *shadowSummary) error {
	var timeout, skipped, failed int64
	const ok = ` FILTER (WHERE s.status = 'ok')`
	err := tx.QueryRow(ctx, `SELECT count(*), count(*)`+ok+`,
		count(*) FILTER (WHERE s.status = 'ok' AND s.active_decision = s.shadow_decision),
		count(*) FILTER (WHERE s.status = 'ok' AND s.active_decision = 'allow' AND s.shadow_decision = 'block'),
		count(*) FILTER (WHERE s.status = 'ok' AND s.active_decision = 'block' AND s.shadow_decision = 'allow'),
		count(*) FILTER (WHERE s.status = 'timeout'), count(*) FILTER (WHERE s.status = 'skipped'),
		count(*) FILTER (WHERE s.status = 'error'),
		avg(s.active_score)`+ok+`,
		percentile_cont(0.5) WITHIN GROUP (ORDER BY s.active_score)`+ok+`,
		percentile_cont(0.95) WITHIN GROUP (ORDER BY s.active_score)`+ok+`,
		avg(s.shadow_score)`+ok+`,
		percentile_cont(0.5) WITHIN GROUP (ORDER BY s.shadow_score)`+ok+`,
		percentile_cont(0.95) WITHIN GROUP (ORDER BY s.shadow_score)`+ok+`,
		avg(s.shadow_score - s.active_score)`+ok+`,
		avg(abs(s.shadow_score - s.active_score))`+ok+`,
		percentile_cont(0.95) WITHIN GROUP (ORDER BY abs(s.shadow_score - s.active_score))`+ok+filter, args...).
		Scan(&s.Total, &s.Compared, &s.Agree, &s.WouldBlock, &s.WouldAllow, &timeout, &skipped, &failed,
			&s.Scores.Active.Mean, &s.Scores.Active.P50, &s.Scores.Active.P95,
			&s.Scores.Shadow.Mean, &s.Scores.Shadow.P50, &s.Scores.Shadow.P95,
			&s.Scores.Delta.Mean, &s.Scores.Delta.MeanAbs, &s.Scores.Delta.P95Abs)
	if err != nil {
		return err
	}
	s.NotCompared = map[string]int64{"timeout": timeout, "skipped": skipped, "error": failed}

	if s.Pairs, err = queryList[shadowPair](ctx, tx,
		`SELECT COALESCE(s.active_model, ''), COALESCE(s.shadow_model, ''), count(*) AS n`+filter+`
		 GROUP BY 1, 2 ORDER BY n DESC, 1, 2 LIMIT 20`, args...); err != nil {
		return err
	}

	type binCount struct {
		Bin    int32
		Active int64
		Shadow int64
	}
	bins, err := queryList[binCount](ctx, tx, fmt.Sprintf(
		`SELECT b, sum(a)::bigint, sum(sh)::bigint FROM (
		   SELECT LEAST(GREATEST(floor(s.active_score * %[1]d), 0), %[1]d - 1)::int AS b, 1 AS a, 0 AS sh`+filter+` AND s.status = 'ok'
		   UNION ALL
		   SELECT LEAST(GREATEST(floor(s.shadow_score * %[1]d), 0), %[1]d - 1)::int, 0, 1`+filter+` AND s.status = 'ok'
		 ) x GROUP BY b`, shadowHistogramBins), args...)
	if err != nil {
		return err
	}
	s.Scores.Histogram = make([]shadowBin, shadowHistogramBins)
	for i := range s.Scores.Histogram {
		s.Scores.Histogram[i] = shadowBin{From: float64(i) / shadowHistogramBins, To: float64(i+1) / shadowHistogramBins}
	}
	for _, b := range bins {
		if b.Bin >= 0 && int(b.Bin) < shadowHistogramBins {
			s.Scores.Histogram[b.Bin].Active, s.Scores.Histogram[b.Bin].Shadow = b.Active, b.Shadow
		}
	}
	return nil
}

type shadowDisagreement struct {
	RequestID      uuid.UUID  `json:"request_id"`
	CreatedAt      time.Time  `json:"created_at"`
	ProjectID      *uuid.UUID `json:"project_id"`
	Action         string     `json:"action"`
	Model          *string    `json:"model"`
	ActiveModel    string     `json:"active_model"`
	ShadowModel    string     `json:"shadow_model"`
	ActiveScore    float32    `json:"active_score"`
	ShadowScore    float32    `json:"shadow_score"`
	ActiveDecision string     `json:"active_decision"`
	ShadowDecision string     `json:"shadow_decision"`
	Direction      string     `json:"direction"`
}

// Directions of a disagreement.
const (
	dirWouldBlock = "would_block" // the active model allowed, the candidate would block
	dirWouldAllow = "would_allow" // the active model blocked, the candidate would allow
)

func listShadowDisagreements(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		pg, err := parsePage(c, false)
		if err != nil {
			return badPage(c, err)
		}
		_, _, _, _, filter, args, err := shadowFilter(c)
		if err != nil {
			return badRequest(c, err.Error())
		}
		filter += ` AND s.status = 'ok' AND s.active_decision IS DISTINCT FROM s.shadow_decision`
		switch c.Query("direction") {
		case "":
		case dirWouldBlock:
			filter += ` AND s.shadow_decision = 'block'`
		case dirWouldAllow:
			filter += ` AND s.shadow_decision = 'allow'`
		default:
			return badRequest(c, "direction must be would_block or would_allow")
		}
		ks := keyset{sort: "s.created_at", id: "s.request_id", desc: true}
		items := []shadowDisagreement{}
		err = tenant.WithOrg(c.Context(), db, orgID(c), func(tx pgx.Tx) error {
			cond, args, err := ks.where(pg, args)
			if err != nil {
				return err
			}
			rows, err := tx.Query(c.Context(),
				`SELECT s.request_id, s.created_at, s.project_id, r.action, r.model,
				        COALESCE(s.active_model, ''), COALESCE(s.shadow_model, ''),
				        s.active_score, s.shadow_score, s.active_decision, s.shadow_decision`+
					strings.Replace(filter, " WHERE ", " JOIN requests r ON r.id = s.request_id WHERE ", 1)+
					cond+ks.orderLimit(pg), args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var d shadowDisagreement
				if err := rows.Scan(&d.RequestID, &d.CreatedAt, &d.ProjectID, &d.Action, &d.Model, &d.ActiveModel,
					&d.ShadowModel, &d.ActiveScore, &d.ShadowScore, &d.ActiveDecision, &d.ShadowDecision); err != nil {
					return err
				}
				d.Direction = dirWouldAllow
				if d.ShadowDecision == "block" {
					d.Direction = dirWouldBlock
				}
				items = append(items, d)
			}
			return rows.Err()
		})
		if errors.Is(err, errBadCursor) {
			return badPage(c, err)
		}
		if err != nil {
			return serverError(c, err)
		}
		items, next := page(items, pg.Limit, func(d shadowDisagreement) pageCursor {
			return timeCursor(d.CreatedAt, d.RequestID.String())
		})
		return pageJSON(c, items, next, -1)
	}
}

// ── Gateway model status ─────────────────────────────────────────────────────

// gatewayModels is what the admin UI shows about the gateway's models. The
// control plane reads the gateway's /readyz (GATEWAY_URL) server side; the UI
// itself never calls the gateway or the Internet. Nothing here needs the
// Internet either: "recommended" comes from the gateway's manifest (the one
// built in, or MODELS_MANIFEST).
type gatewayModels struct {
	Configured      bool         `json:"configured"`
	Reachable       bool         `json:"reachable"`
	Error           string       `json:"error,omitempty"`
	CheckedAt       time.Time    `json:"checked_at"`
	L2Model         *string      `json:"l2_model"`
	L2Verified      bool         `json:"l2_verified"`
	Recommended     *string      `json:"recommended"`
	Installed       []string     `json:"installed"`
	UpdateAvailable bool         `json:"update_available"`
	Shadow          gwShadow     `json:"shadow"`
	Reload          gwReloadInfo `json:"reload"`
	// Layers are the detection layers that run (l1, l2, l3); null when the
	// gateway did not say.
	Layers []string `json:"layers"`
	// Fusion is the combiner (logreg or max); empty when unknown.
	Fusion string `json:"fusion,omitempty"`
	// L1Floor is FUSION_L1_FLOOR as the gateway applies it (0: off); null
	// when the gateway does not report it (before the floor existed).
	L1Floor *float64 `json:"l1_floor"`
	// GatewayVersion is the gateway's version from /readyz; empty when it
	// does not say. The admin UI puts it in bypass and false-positive reports.
	GatewayVersion string `json:"gateway_version,omitempty"`
}

type gwShadow struct {
	Enabled bool    `json:"enabled"`
	Model   *string `json:"model"`
	Error   string  `json:"error,omitempty"`
}

type gwReloadInfo struct {
	Generation int64      `json:"generation"`
	At         *time.Time `json:"at"`
	Error      *string    `json:"error"`
}

// gatewayReadyz is the part of the gateway's /readyz read here.
type gatewayReadyz struct {
	Version  string `json:"version"`
	Detector struct {
		Layers  []string `json:"layers"`
		Fusion  string   `json:"fusion"`
		L1Floor *float64 `json:"l1_floor"`
		Models  *struct {
			Generation      int64    `json:"generation"`
			L2Model         string   `json:"l2_model"`
			L2Verified      bool     `json:"l2_verified"`
			Recommended     string   `json:"recommended"`
			UpdateAvailable bool     `json:"update_available"`
			Installed       []string `json:"installed"`
			Shadow          struct {
				Enabled bool   `json:"enabled"`
				Model   string `json:"model"`
				Error   string `json:"error"`
			} `json:"shadow"`
			Reload struct {
				At    *time.Time `json:"at"`
				Error string     `json:"error"`
			} `json:"reload"`
		} `json:"models"`
	} `json:"detector"`
	// Input is the gateway's input limits (input_settings.go); nil from
	// gateways before 0.7.0.
	Input *gatewayInput `json:"input"`
}

// gatewayInput is the input part of the gateway's /readyz: the instance
// limits an organization's input settings stay within.
type gatewayInput struct {
	MaxScanTokens         int      `json:"max_scan_tokens"`
	MaxInputTokensCeiling int      `json:"max_input_tokens_ceiling"`
	PDFExtract            bool     `json:"pdf_extract"`
	UnscannedParts        string   `json:"unscanned_parts"`
	ReadableFileTypes     []string `json:"readable_file_types"`
}

// gatewayStatusTimeout bounds the /readyz call.
const gatewayStatusTimeout = 3 * time.Second

// gatewayStatusClient is the client that reads the gateway's /readyz.
func gatewayStatusClient(settings *appSettings) *http.Client {
	if settings.gatewayClient != nil {
		return settings.gatewayClient
	}
	return &http.Client{Timeout: gatewayStatusTimeout,
		// /readyz never redirects; following one could reach another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func getGatewayModels(settings *appSettings) fiber.Handler {
	client := gatewayStatusClient(settings)
	return func(c *fiber.Ctx) error {
		out := gatewayModels{CheckedAt: time.Now().UTC(), Installed: []string{}}
		if settings.gatewayURL == "" {
			return c.JSON(out)
		}
		out.Configured = true
		st, err := fetchReadyz(c.Context(), client, settings.gatewayURL)
		if err != nil {
			out.Error = err.Error()
			return c.JSON(out)
		}
		out.Reachable = true
		out.GatewayVersion = st.Version
		out.Layers, out.Fusion, out.L1Floor = st.Detector.Layers, st.Detector.Fusion, st.Detector.L1Floor
		m := st.Detector.Models
		if m == nil {
			out.Error = "the gateway does not report its models (an older version?)"
			return c.JSON(out)
		}
		str := func(s string) *string {
			if s == "" {
				return nil
			}
			return &s
		}
		out.L2Model, out.L2Verified, out.Recommended = str(m.L2Model), m.L2Verified, str(m.Recommended)
		out.UpdateAvailable = m.UpdateAvailable
		if m.Installed != nil {
			out.Installed = m.Installed
		}
		out.Shadow = gwShadow{Enabled: m.Shadow.Enabled, Model: str(m.Shadow.Model), Error: m.Shadow.Error}
		out.Reload = gwReloadInfo{Generation: m.Generation, At: m.Reload.At, Error: str(m.Reload.Error)}
		return c.JSON(out)
	}
}

// fetchReadyz reads base/readyz. A 503 still carries the body (degraded).
func fetchReadyz(ctx context.Context, client *http.Client, base string) (gatewayReadyz, error) {
	var st gatewayReadyz
	u, err := url.Parse(strings.TrimRight(base, "/") + "/readyz")
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return st, errors.New("GATEWAY_URL is not a valid http(s) URL")
	}
	ctx, cancel := context.WithTimeout(ctx, gatewayStatusTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return st, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return st, errors.New("gateway unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return st, fmt.Errorf("gateway /readyz answered %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return st, errors.New("gateway /readyz: unreadable answer")
	}
	return st, nil
}
