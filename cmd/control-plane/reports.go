// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The periodic report (RF-5f318378): the request log of one organization
// aggregated per period as CSV, for the people who do not read the
// dashboard. It holds counts only, never prompt or answer content, and is
// read by whoever may read the request log (viewer).
//
//	GET /organizations/:orgId/reports/requests.csv?window=24h|7d|30d
//	GET /organizations/:orgId/reports/requests.csv?from=<RFC 3339>&to=<RFC 3339>
//
// One row per period and item, in long form, so a spreadsheet pivots it:
//
//	period_start,period_end,section,key,requests,blocked
//	2026-11-10T00:00:00Z,2026-11-11T00:00:00Z,total,all,1200,37
//	2026-11-10T00:00:00Z,2026-11-11T00:00:00Z,action,block,37,37
//	2026-11-10T00:00:00Z,2026-11-11T00:00:00Z,reason,jailbreak,20,20
//	2026-11-10T00:00:00Z,2026-11-11T00:00:00Z,reason,policy:high l2,17,17
//	2026-11-10T00:00:00Z,2026-11-11T00:00:00Z,project,Billing bot,900,30
//	2026-11-10T00:00:00Z,2026-11-11T00:00:00Z,api_key,gs_3fa9c1d2,900,30
//
// Sections: total (key all), action (allow, block, route, error), reason
// (why a request was blocked: the policy rule as policy:<name>, else the
// detector's label, else other), project (the project's name, or none) and
// api_key (the key's prefix, or none). Periods are hours up to 48 hours
// and days (UTC) beyond, like the dashboard; empty periods are left out.
//
// There is no scheduler for per-organization jobs in the control plane
// (retention and alert workers are instance-wide), so the report is pulled
// through the API or the dashboard; a cron job with curl schedules it.

// maxReportSpan bounds an explicit from..to.
const maxReportSpan = 92 * 24 * time.Hour

// reportRow is one line of the CSV.
type reportRow struct {
	Start    time.Time
	End      time.Time
	Section  string
	Key      string
	Requests int64
	Blocked  int64
}

var reportHeader = []string{"period_start", "period_end", "section", "key", "requests", "blocked"}

// writeReportCSV renders rows with the header, RFC 3339 times in UTC.
func writeReportCSV(w io.Writer, rows []reportRow) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(reportHeader); err != nil {
		return err
	}
	for _, r := range rows {
		if err := cw.Write([]string{
			r.Start.UTC().Format(time.RFC3339), r.End.UTC().Format(time.RFC3339), r.Section, r.Key,
			strconv.FormatInt(r.Requests, 10), strconv.FormatInt(r.Blocked, 10),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

var errReportRange = errors.New("report range")

// reportRange reads window, or from and to, from the query: the span, its
// bucket (hour or day) and the file name's stamp.
func reportRange(window, fromRaw, toRaw string, now time.Time) (from, to time.Time, bucket string, err error) {
	if fromRaw == "" && toRaw == "" {
		_, d, b, err := parseDashboardWindow(window)
		if err != nil {
			return from, to, "", fmt.Errorf("%w: %v", errReportRange, err)
		}
		return now.Add(-d).UTC(), now.UTC(), b, nil
	}
	if window != "" {
		return from, to, "", fmt.Errorf("%w: give window, or from and to, not both", errReportRange)
	}
	if from, err = time.Parse(time.RFC3339, fromRaw); err != nil {
		return from, to, "", fmt.Errorf("%w: from must be an RFC 3339 time", errReportRange)
	}
	to = now
	if toRaw != "" {
		if to, err = time.Parse(time.RFC3339, toRaw); err != nil {
			return from, to, "", fmt.Errorf("%w: to must be an RFC 3339 time", errReportRange)
		}
	}
	if !to.After(from) {
		return from, to, "", fmt.Errorf("%w: to must be after from", errReportRange)
	}
	if to.Sub(from) > maxReportSpan {
		return from, to, "", fmt.Errorf("%w: at most %d days", errReportRange, int(maxReportSpan.Hours()/24))
	}
	bucket = "day"
	if to.Sub(from) <= 48*time.Hour {
		bucket = "hour"
	}
	return from.UTC(), to.UTC(), bucket, nil
}

// reportFilename names the download: guard-spec-<slug>-<from>-<to>.csv.
func reportFilename(slug string, from, to time.Time) string {
	stamp := func(t time.Time) string { return t.UTC().Format("20060102T1504") }
	clean := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, strings.ToLower(slug))
	return fmt.Sprintf("guard-spec-%s-%s-%s.csv", clean, stamp(from), stamp(to))
}

// queryReport collects the rows of one org over from..to in bucket-sized
// periods. filter and args select the requests (" FROM requests WHERE
// ..."), as for the dashboard.
func queryReport(ctx context.Context, tx pgx.Tx, org uuid.UUID, filter string, args []any, bucket string) ([]reportRow, error) {
	type agg struct {
		Start    time.Time
		Key      string
		Requests int64
		Blocked  int64
	}
	// $N is the bucket; the key expression differs per section.
	n := len(args) + 1
	period := fmt.Sprintf(`date_trunc($%d, created_at, 'UTC')`, n)
	args = append(args, bucket)
	sections := []struct {
		name  string
		key   string
		extra string
	}{
		{"total", `'all'`, ""},
		{"action", `action`, ""},
		// Blocked requests only: the rule, else the label, else other.
		{"reason", `COALESCE('policy:' || (SELECT r->>'name' FROM policies p, jsonb_array_elements(p.rules) r
		   WHERE p.org_id = $1 AND r->>'id' = requests.rule_id::text LIMIT 1),
		   CASE WHEN rule_id IS NOT NULL THEN 'policy:' || rule_id::text END,
		   NULLIF(lower(btrim(injection_label)), ''), 'other')`, " AND action = 'block'"},
		{"project", `COALESCE((SELECT name FROM projects pr WHERE pr.id = requests.project_id), 'none')`, ""},
		{"api_key", `COALESCE((SELECT key_prefix FROM api_keys k WHERE k.key_hash = requests.api_key_hash), 'none')`, ""},
	}
	var out []reportRow
	step := time.Hour
	if bucket == "day" {
		step = 24 * time.Hour
	}
	for _, s := range sections {
		rows, err := queryList[agg](ctx, tx,
			`SELECT `+period+` AS period, `+s.key+` AS k, count(*), count(*) FILTER (WHERE action = 'block')`+
				filter+s.extra+` GROUP BY period, k ORDER BY period, k`, args...)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
		for _, a := range rows {
			start := a.Start.UTC()
			out = append(out, reportRow{Start: start, End: start.Add(step), Section: s.name, Key: a.Key, Requests: a.Requests, Blocked: a.Blocked})
		}
	}
	sortReportRows(out)
	return out, nil
}

// sortReportRows orders rows by period, then section (total, action,
// reason, project, api_key), then key.
func sortReportRows(rows []reportRow) {
	order := map[string]int{"total": 0, "action": 1, "reason": 2, "project": 3, "api_key": 4}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if !a.Start.Equal(b.Start) {
			return a.Start.Before(b.Start)
		}
		if order[a.Section] != order[b.Section] {
			return order[a.Section] < order[b.Section]
		}
		return a.Key < b.Key
	})
}

// getRequestsReport answers GET /organizations/:orgId/reports/requests.csv.
func getRequestsReport(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		from, to, bucket, err := reportRange(c.Query("window"), c.Query("from"), c.Query("to"), time.Now())
		if err != nil {
			return badRequest(c, strings.TrimPrefix(err.Error(), "report range: "))
		}
		args := []any{org, from, to}
		filter := ` FROM requests WHERE org_id = $1 AND created_at >= $2 AND created_at < $3`
		if raw := c.Query("project_id"); raw != "" {
			id, err := uuid.Parse(raw)
			if err != nil {
				return badRequest(c, "invalid project_id")
			}
			args = append(args, id)
			filter += fmt.Sprintf(" AND project_id = $%d", len(args))
		}
		var (
			rows []reportRow
			slug string
		)
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := tx.QueryRow(c.Context(), `SELECT slug FROM organizations WHERE id = $1`, org).Scan(&slug); err != nil {
				return err
			}
			rows, err = queryReport(c.Context(), tx, org, filter, args, bucket)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		var buf bytes.Buffer
		if err := writeReportCSV(&buf, rows); err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "report.downloaded", "requests.csv", map[string]any{
			"from": from, "to": to, "bucket": bucket, "rows": len(rows), "project_id": c.Query("project_id")})
		c.Set(fiber.HeaderContentType, "text/csv; charset=utf-8")
		c.Set(fiber.HeaderContentDisposition, `attachment; filename="`+reportFilename(slug, from, to)+`"`)
		c.Set(fiber.HeaderCacheControl, "no-store")
		return c.Send(buf.Bytes())
	}
}
