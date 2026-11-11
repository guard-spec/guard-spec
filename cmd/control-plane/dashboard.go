// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The dashboard aggregates the request log of one org over a window that
// ends now: totals, latency percentiles, a time series and top lists, all
// computed in Postgres. Whoever may read /requests may read it (viewer).

// dashboardWindows are the windows the dashboard accepts; 24h is the default.
var dashboardWindows = map[string]time.Duration{
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

var errDashboardWindow = errors.New("window must be 24h, 7d or 30d")

// dashboardTopN is the length of each top list.
const dashboardTopN = 5

type dashActionCount struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

type dashBucket struct {
	Start   time.Time `json:"start"`
	Count   int64     `json:"count"`
	Blocked int64     `json:"blocked"`
}

type dashLabel struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// dashRule is a rule that decided requests; the names are null once the rule
// is gone from the org's policies.
type dashRule struct {
	RuleID uuid.UUID `json:"rule_id"`
	Rule   *string   `json:"rule"`
	Policy *string   `json:"policy"`
	Count  int64     `json:"count"`
}

// dashProject counts the requests of a project; project_id and name are null
// for requests without one.
type dashProject struct {
	ProjectID *uuid.UUID `json:"project_id"`
	Name      *string    `json:"name"`
	Count     int64      `json:"count"`
	Blocked   int64      `json:"blocked"`
}

// dashKey counts the requests of an API key, by its prefix and alias;
// "none" for requests without a key the org still has.
type dashKey struct {
	Prefix  string  `json:"key_prefix"`
	Alias   *string `json:"alias"`
	Count   int64   `json:"count"`
	Blocked int64   `json:"blocked"`
}

type dashLatency struct {
	P50 *float64 `json:"p50"`
	P95 *float64 `json:"p95"`
	P99 *float64 `json:"p99"`
}

type dashboardStats struct {
	Window    string            `json:"window"`
	From      time.Time         `json:"from"`
	To        time.Time         `json:"to"`
	Bucket    string            `json:"bucket"` // hour or day, in UTC
	ProjectID *uuid.UUID        `json:"project_id"`
	Total     int64             `json:"total"`
	Blocked   int64             `json:"blocked"`
	BlockRate float64           `json:"block_rate"`
	ByAction  []dashActionCount `json:"by_action"`
	// percentile_cont of latency_ms; null when no row has a latency.
	Latency dashLatency `json:"latency_ms"`
	// One entry per bucket, oldest first, empty buckets included.
	Series []dashBucket `json:"series"`
	// Injection labels other than benign, in lower case (the gateway
	// stores BENIGN, the classifier jailbreak).
	TopLabels   []dashLabel   `json:"top_labels"`
	TopRules    []dashRule    `json:"top_rules"`
	TopProjects []dashProject `json:"top_projects"`
	// The most attacked: the projects and API keys with the most refused
	// requests (blocked > 0 only), for the security overview.
	TopBlockedProjects []dashProject `json:"top_blocked_projects"`
	TopBlockedKeys     []dashKey     `json:"top_blocked_keys"`
}

// parseDashboardWindow returns the window (24h when raw is empty) and its
// bucket: hours up to 48 hours, days beyond.
func parseDashboardWindow(raw string) (name string, d time.Duration, bucket string, err error) {
	if raw == "" {
		raw = "24h"
	}
	d, ok := dashboardWindows[raw]
	if !ok {
		return "", 0, "", errDashboardWindow
	}
	if d <= 48*time.Hour {
		return raw, d, "hour", nil
	}
	return raw, d, "day", nil
}

// truncateBucket returns the UTC start of the bucket holding t.
func truncateBucket(t time.Time, bucket string) time.Time {
	t = t.UTC()
	if bucket == "day" {
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
	return t.Truncate(time.Hour)
}

// fillSeries returns one bucket for each step from the bucket of from to the
// bucket of to, with the counts of got (keyed by bucket start) or zero.
func fillSeries(from, to time.Time, bucket string, got map[time.Time]dashBucket) []dashBucket {
	step := time.Hour
	if bucket == "day" {
		step = 24 * time.Hour
	}
	out := []dashBucket{}
	for b := truncateBucket(from, bucket); !b.After(to); b = b.Add(step) {
		c := got[b]
		c.Start = b
		out = append(out, c)
	}
	return out
}

func getDashboard(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		window, d, bucket, err := parseDashboardWindow(c.Query("window"))
		if err != nil {
			return badRequest(c, err.Error())
		}
		s := dashboardStats{Window: window, Bucket: bucket, To: time.Now().UTC()}
		s.From = s.To.Add(-d)
		// The explicit org filter lets Postgres use idx_requests_org; row
		// level security is the backstop.
		args := []any{org, s.From, s.To}
		filter := ` FROM requests WHERE org_id = $1 AND created_at >= $2 AND created_at < $3`
		if raw := c.Query("project_id"); raw != "" {
			id, err := uuid.Parse(raw)
			if err != nil {
				return badRequest(c, "invalid project_id")
			}
			s.ProjectID = &id
			args = append(args, id)
			filter += fmt.Sprintf(" AND project_id = $%d", len(args))
		}
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return queryDashboard(c.Context(), tx, filter, args, &s)
		})
		if err != nil {
			return serverError(c, err)
		}
		if s.Total > 0 {
			s.BlockRate = float64(s.Blocked) / float64(s.Total)
		}
		return c.JSON(s)
	}
}

// queryDashboard fills s from the requests that filter (" FROM requests
// WHERE ...", with args) selects.
func queryDashboard(ctx context.Context, tx pgx.Tx, filter string, args []any, s *dashboardStats) error {
	err := tx.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE action = 'block'),
		        percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms),
		        percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms),
		        percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms)`+filter, args...).
		Scan(&s.Total, &s.Blocked, &s.Latency.P50, &s.Latency.P95, &s.Latency.P99)
	if err != nil {
		return err
	}

	if s.ByAction, err = queryList[dashActionCount](ctx, tx,
		`SELECT action, count(*) AS n`+filter+` GROUP BY action ORDER BY n DESC, action`, args...); err != nil {
		return err
	}

	// The bucket is a parameter; date_trunc in UTC so days do not follow
	// the session time zone.
	buckets, err := queryList[dashBucket](ctx, tx,
		fmt.Sprintf(`SELECT date_trunc($%d, created_at, 'UTC'), count(*), count(*) FILTER (WHERE action = 'block')`, len(args)+1)+
			filter+` GROUP BY 1`, append(args, s.Bucket)...)
	if err != nil {
		return err
	}
	got := make(map[time.Time]dashBucket, len(buckets))
	for _, b := range buckets {
		got[b.Start.UTC()] = b
	}
	s.Series = fillSeries(s.From, s.To, s.Bucket, got)

	if s.TopLabels, err = queryList[dashLabel](ctx, tx,
		fmt.Sprintf(`SELECT lower(btrim(injection_label)) AS l, count(*) AS n`+filter+`
		  AND lower(btrim(injection_label)) NOT IN ('', 'benign') GROUP BY l ORDER BY n DESC, l LIMIT %d`, dashboardTopN), args...); err != nil {
		return err
	}

	// Rule names come from the org's policies (rules is a JSON array whose
	// entries carry the id); a rule may also be gone.
	if s.TopRules, err = queryList[dashRule](ctx, tx,
		fmt.Sprintf(`SELECT t.rule_id, pr.rule, pr.policy, t.n FROM (
		   SELECT rule_id, count(*) AS n`+filter+` AND rule_id IS NOT NULL
		   GROUP BY rule_id ORDER BY n DESC, rule_id LIMIT %d) t
		 LEFT JOIN LATERAL (
		   SELECT r->>'name' AS rule, p.name AS policy
		   FROM policies p, jsonb_array_elements(p.rules) r
		   WHERE p.org_id = $1 AND r->>'id' = t.rule_id::text
		   LIMIT 1) pr ON true
		 ORDER BY t.n DESC, t.rule_id`, dashboardTopN), args...); err != nil {
		return err
	}

	s.TopProjects, err = queryList[dashProject](ctx, tx,
		fmt.Sprintf(`SELECT t.project_id, p.name, t.n, t.blocked FROM (
		   SELECT project_id, count(*) AS n, count(*) FILTER (WHERE action = 'block') AS blocked`+filter+`
		   GROUP BY project_id ORDER BY n DESC, project_id NULLS LAST LIMIT %d) t
		 LEFT JOIN projects p ON p.id = t.project_id AND p.org_id = $1
		 ORDER BY t.n DESC, t.project_id NULLS LAST`, dashboardTopN), args...)
	if err != nil {
		return err
	}

	if s.TopBlockedProjects, err = queryList[dashProject](ctx, tx,
		fmt.Sprintf(`SELECT t.project_id, p.name, t.n, t.blocked FROM (
		   SELECT project_id, count(*) AS n, count(*) FILTER (WHERE action = 'block') AS blocked`+filter+`
		   GROUP BY project_id HAVING count(*) FILTER (WHERE action = 'block') > 0
		   ORDER BY blocked DESC, n DESC, project_id NULLS LAST LIMIT %d) t
		 LEFT JOIN projects p ON p.id = t.project_id AND p.org_id = $1
		 ORDER BY t.blocked DESC, t.n DESC, t.project_id NULLS LAST`, dashboardTopN), args...); err != nil {
		return err
	}

	// Keys by their hash (the request log has no key id); a key the org no
	// longer has, or none, reads as "none".
	s.TopBlockedKeys, err = queryList[dashKey](ctx, tx,
		fmt.Sprintf(`SELECT COALESCE(k.key_prefix, 'none'), k.alias, t.n, t.blocked FROM (
		   SELECT api_key_hash, count(*) AS n, count(*) FILTER (WHERE action = 'block') AS blocked`+filter+`
		   GROUP BY api_key_hash HAVING count(*) FILTER (WHERE action = 'block') > 0
		   ORDER BY blocked DESC, n DESC, api_key_hash NULLS LAST LIMIT %d) t
		 LEFT JOIN api_keys k ON k.key_hash = t.api_key_hash AND k.org_id = $1
		 ORDER BY t.blocked DESC, t.n DESC, 1`, dashboardTopN), args...)
	return err
}

// queryList scans the rows of sql into T, column by field in order.
func queryList[T any](ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]T, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[T])
}
