// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/alerts/channels"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NOTIFY channels besides events.Channel. The payload of OutboxChannel is an
// org id, of NotificationsChannel a user id.
const (
	OutboxChannel        = "guardspec_outbox"
	NotificationsChannel = "guardspec_notifications"
)

const (
	eventBatch   = 500
	maxBatches   = 10
	hitRetention = 24 * time.Hour // the longest window
	maxSamples   = 10
	// MaxOutboxPerMinute caps the deliveries one org queues per minute.
	MaxOutboxPerMinute = 1000
)

// Caps says which personal channels the instance can deliver to.
type Caps struct {
	Telegram bool // TELEGRAM_BOT_TOKEN is set
	Slack    bool // SLACK_BOT_TOKEN is set
	SMTP     bool // SMTP_URL and SMTP_FROM are set
}

// Engine evaluates rules over new events and queues notifications.
type Engine struct {
	DB        *pgxpool.Pool
	PublicURL string // PUBLIC_BASE_URL, for links
	Caps      Caps
	Lang      string // language of in-app notification text: en or vi
	Now       func() time.Time

	mu     sync.Mutex
	conds  map[uuid.UUID]condEntry
	pruned map[uuid.UUID]time.Time
}

type condEntry struct {
	updated time.Time
	cond    *policy.Condition
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// condition returns the compiled condition of r, cached by update time.
func (e *Engine) condition(r *Rule) (*policy.Condition, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.conds[r.ID]; ok && c.updated.Equal(r.UpdatedAt) {
		return c.cond, nil
	}
	c, err := policy.CompileCondition(r.ConditionCEL, Fields)
	if err != nil {
		return nil, err
	}
	if e.conds == nil || len(e.conds) > 10000 {
		e.conds = map[uuid.UUID]condEntry{}
	}
	e.conds[r.ID] = condEntry{updated: r.UpdatedAt, cond: c}
	return c, nil
}

// RuleColumns are the columns ScanRule reads.
const RuleColumns = `id, org_id, name, enabled, event_types, condition, condition_cel, threshold, window_seconds,
	severity::text, throttle_seconds, group_by, quiet_hours, auto_resolve, recipients, channel_ids, created_by,
	created_at, updated_at`

// ScanRule reads a row of RuleColumns.
func ScanRule(row pgx.Row) (Rule, error) {
	var r Rule
	var quiet, rcpt []byte
	err := row.Scan(&r.ID, &r.OrgID, &r.Name, &r.Enabled, &r.EventTypes, &r.Condition, &r.ConditionCEL, &r.Threshold,
		&r.WindowSeconds, &r.Severity, &r.ThrottleSeconds, &r.GroupBy, &quiet, &r.AutoResolve, &rcpt, &r.ChannelIDs,
		&r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	if len(quiet) > 0 && string(quiet) != "null" {
		r.QuietHours = &QuietHours{}
		if err := json.Unmarshal(quiet, r.QuietHours); err != nil {
			return r, err
		}
	}
	if err := json.Unmarshal(rcpt, &r.Recipients); err != nil {
		return r, err
	}
	if r.Recipients.UserIDs == nil {
		r.Recipients.UserIDs = []uuid.UUID{}
	}
	if r.Recipients.GroupIDs == nil {
		r.Recipients.GroupIDs = []uuid.UUID{}
	}
	if r.Recipients.Roles == nil {
		r.Recipients.Roles = []string{}
	}
	if r.GroupBy == nil {
		r.GroupBy = []string{}
	}
	if r.ChannelIDs == nil {
		r.ChannelIDs = []uuid.UUID{}
	}
	return r, nil
}

func loadRules(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]Rule, error) {
	rows, err := tx.Query(ctx, `SELECT `+RuleColumns+` FROM alert_rules WHERE org_id = $1 AND enabled`, org)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Rule, error) { return ScanRule(r) })
}

// ProcessOrg evaluates the org's rules over its unprocessed events, records
// alerts and queues notifications, and resolves alerts whose count fell
// below the threshold. It returns the number of events processed. Another
// replica working on the org makes it return 0 at once
// (pg_try_advisory_xact_lock).
func (e *Engine) ProcessOrg(ctx context.Context, org uuid.UUID) (int, error) {
	total := 0
	for i := 0; i < maxBatches; i++ {
		n, more, err := e.processBatch(ctx, org, i == 0)
		total += n
		if err != nil || !more {
			return total, err
		}
	}
	return total, nil
}

func (e *Engine) processBatch(ctx context.Context, org uuid.UUID, housekeeping bool) (n int, more bool, err error) {
	err = tenant.WithOrg(ctx, e.DB, org, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))`,
			"guardspec.alerts:"+org.String()).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			return nil
		}
		rules, err := loadRules(ctx, tx, org)
		if err != nil {
			return err
		}
		evs, err := loadEvents(ctx, tx, org)
		if err != nil {
			return err
		}
		n, more = len(evs), len(evs) == eventBatch
		now := e.now()
		if len(evs) > 0 {
			if err := e.evaluate(ctx, tx, org, rules, evs, now); err != nil {
				return err
			}
		}
		if housekeeping {
			if err := e.resolve(ctx, tx, org, rules, now); err != nil {
				return err
			}
			if e.pruneDue(org, now) {
				if err := prune(ctx, tx, org, now); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return n, more, err
}

// Retention of alert data, in batches of pruneBatch rows per pass.
const (
	EventRetention        = 30 * 24 * time.Hour
	DeliveryRetention     = 30 * 24 * time.Hour
	NotificationRetention = 90 * 24 * time.Hour
	pruneBatch            = 1000
)

// pruneDue reports whether org was not pruned in the last minute.
func (e *Engine) pruneDue(org uuid.UUID, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pruned == nil || len(e.pruned) > 100000 {
		e.pruned = map[uuid.UUID]time.Time{}
	}
	if last, ok := e.pruned[org]; ok && now.Sub(last) < time.Minute {
		return false
	}
	e.pruned[org] = now
	return true
}

// PruneOrg runs the retention of org now (tests; the worker prunes on its own).
func PruneOrg(ctx context.Context, db *pgxpool.Pool, org uuid.UUID, now time.Time) error {
	return tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error { return prune(ctx, tx, org, now) })
}

// prune deletes old rule hits, processed events, finished deliveries and
// read in-app notifications of org.
func prune(ctx context.Context, tx pgx.Tx, org uuid.UUID, now time.Time) error {
	stmts := []struct {
		q    string
		keep time.Duration
	}{
		{`DELETE FROM alert_rule_hits WHERE org_id = $1 AND occurred_at < $2`, hitRetention},
		{`DELETE FROM events WHERE id IN (SELECT id FROM events WHERE org_id = $1 AND processed_at IS NOT NULL
		   AND occurred_at < $2 LIMIT ` + fmt.Sprint(pruneBatch) + `)`, EventRetention},
		{`DELETE FROM notification_outbox WHERE id IN (SELECT id FROM notification_outbox WHERE org_id = $1
		   AND state IN ('sent', 'dead') AND created_at < $2 LIMIT ` + fmt.Sprint(pruneBatch) + `)`, DeliveryRetention},
		{`DELETE FROM notifications WHERE id IN (SELECT id FROM notifications WHERE org_id = $1
		   AND read_at IS NOT NULL AND created_at < $2 LIMIT ` + fmt.Sprint(pruneBatch) + `)`, NotificationRetention},
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s.q, org, now.Add(-s.keep)); err != nil {
			return err
		}
	}
	return nil
}

func loadEvents(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]events.Event, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, project_id, type, severity::text, occurred_at, attrs FROM events
		 WHERE org_id = $1 AND processed_at IS NULL ORDER BY created_at, id LIMIT $2 FOR UPDATE SKIP LOCKED`,
		org, eventBatch)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (events.Event, error) {
		ev := events.Event{OrgID: org}
		var attrs []byte
		if err := r.Scan(&ev.ID, &ev.ProjectID, &ev.Type, &ev.Severity, &ev.OccurredAt, &attrs); err != nil {
			return ev, err
		}
		if err := json.Unmarshal(attrs, &ev.Attrs); err != nil {
			ev.Attrs = map[string]any{}
		}
		return ev, nil
	})
}

// touched is a rule and dedupe key that got new hits in a batch.
type touched struct {
	rule    *Rule
	key     string
	group   map[string]string
	project *uuid.UUID
	events  []uuid.UUID
}

func (e *Engine) evaluate(ctx context.Context, tx pgx.Tx, org uuid.UUID, rules []Rule, evs []events.Event, now time.Time) error {
	hits := map[string]*touched{}
	var order []string
	var hitRules, hitEvents []uuid.UUID
	var hitKeys []string
	var hitTimes []time.Time
	ids := make([]uuid.UUID, 0, len(evs))
	for i := range evs {
		ev := &evs[i]
		ids = append(ids, ev.ID)
		var vars map[string]any
		for j := range rules {
			r := &rules[j]
			if !slices.Contains(r.EventTypes, ev.Type) {
				continue
			}
			if vars == nil {
				vars = Vars(ev)
			}
			cond, err := e.condition(r)
			if err != nil {
				slog.Warn("alert rule condition does not compile; rule skipped", "rule", r.ID, "err", err)
				continue
			}
			ok, err := cond.Match(ctx, vars)
			if err != nil {
				slog.Warn("alert rule condition failed", "rule", r.ID, "err", err)
				continue
			}
			if !ok {
				continue
			}
			key, group := DedupeKey(r.GroupBy, vars)
			id := r.ID.String() + "\x00" + key
			t, seen := hits[id]
			if !seen {
				t = &touched{rule: r, key: key, group: group}
				hits[id] = t
				order = append(order, id)
			}
			t.events = append(t.events, ev.ID)
			if ev.ProjectID != nil {
				t.project = ev.ProjectID
			}
			hitRules, hitEvents, hitKeys, hitTimes = append(hitRules, r.ID), append(hitEvents, ev.ID),
				append(hitKeys, key), append(hitTimes, ev.OccurredAt)
		}
	}
	if len(hitRules) > 0 {
		if _, err := tx.Exec(ctx,
			`INSERT INTO alert_rule_hits (org_id, rule_id, event_id, dedupe_key, occurred_at)
			 SELECT $1, u.r, u.e, u.k, u.t FROM unnest($2::uuid[], $3::uuid[], $4::text[], $5::timestamptz[]) AS u(r, e, k, t)
			 ON CONFLICT DO NOTHING`, org, hitRules, hitEvents, hitKeys, hitTimes); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE events SET processed_at = $2 WHERE id = ANY($1)`, ids, now); err != nil {
		return err
	}
	for _, id := range order {
		if err := e.fire(ctx, tx, org, hits[id], now); err != nil {
			return err
		}
	}
	return nil
}

// alertRow is what notifications need of an alert.
type alertRow struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	RuleName  string
	Key       string
	Group     map[string]string
	ProjectID *uuid.UUID
	Severity  string
	FirstAt   time.Time
	LastAt    time.Time
	Count     int
	Samples   []uuid.UUID
	Test      bool
}

func (e *Engine) windowCount(ctx context.Context, tx pgx.Tx, r *Rule, key string, now time.Time) (int, time.Time, time.Time, error) {
	var n int
	var first, last *time.Time
	err := tx.QueryRow(ctx,
		`SELECT count(*), min(occurred_at), max(occurred_at) FROM alert_rule_hits
		 WHERE rule_id = $1 AND dedupe_key = $2 AND occurred_at > $3`,
		r.ID, key, now.Add(-time.Duration(r.WindowSeconds)*time.Second)).Scan(&n, &first, &last)
	if err != nil || n == 0 {
		return 0, time.Time{}, time.Time{}, err
	}
	return n, *first, *last, nil
}

// windowSamples returns the newest hits of the window, oldest first.
func windowSamples(ctx context.Context, tx pgx.Tx, r *Rule, key string, now time.Time) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx,
		`SELECT event_id FROM alert_rule_hits WHERE rule_id = $1 AND dedupe_key = $2 AND occurred_at > $3
		 ORDER BY occurred_at DESC, event_id LIMIT $4`,
		r.ID, key, now.Add(-time.Duration(r.WindowSeconds)*time.Second), maxSamples)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	slices.Reverse(ids)
	return ids, err
}

// fire records or updates the firing alert of t and notifies unless the
// throttle holds it back.
func (e *Engine) fire(ctx context.Context, tx pgx.Tx, org uuid.UUID, t *touched, now time.Time) error {
	r := t.rule
	count, first, last, err := e.windowCount(ctx, tx, r, t.key, now)
	if err != nil {
		return err
	}
	if count < r.Threshold {
		return nil
	}
	group, _ := json.Marshal(t.group)
	samples, err := windowSamples(ctx, tx, r, t.key, now)
	if err != nil {
		return err
	}
	a := alertRow{OrgID: org, RuleName: r.Name, Key: t.key, Group: t.group, ProjectID: t.project, Severity: r.Severity,
		Count: count, LastAt: last}
	var existing []uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT id, first_at, sample_event_ids FROM alerts WHERE rule_id = $1 AND dedupe_key = $2 AND state = 'firing' FOR UPDATE`,
		r.ID, t.key).Scan(&a.ID, &a.FirstAt, &existing)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		a.FirstAt = first
		a.Samples = samples
		err = tx.QueryRow(ctx,
			`INSERT INTO alerts (org_id, rule_id, rule_name, dedupe_key, group_values, project_id, window_start, state,
			                     severity, first_at, last_at, count, sample_event_ids)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, 'firing', $8::alert_severity, $9, $10, $11, $12)
			 ON CONFLICT DO NOTHING RETURNING id`,
			org, r.ID, r.Name, t.key, group, t.project, now, r.Severity, first, last, count, a.Samples).Scan(&a.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // another transaction opened it; the advisory lock makes this rare
		}
		if err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		a.Samples = lastN(append(existing, samples...), maxSamples)
		if _, err := tx.Exec(ctx,
			`UPDATE alerts SET count = GREATEST(count, $2), last_at = GREATEST(last_at, $3), sample_event_ids = $4,
			        project_id = COALESCE($5, project_id)
			 WHERE id = $1`, a.ID, count, last, a.Samples, t.project); err != nil {
			return err
		}
	}
	// Throttle: one notification per rule and dedupe key per throttle window,
	// across alert episodes.
	var lastNotified *time.Time
	if err := tx.QueryRow(ctx,
		`SELECT max(last_notified_at) FROM alerts WHERE rule_id = $1 AND dedupe_key = $2`, r.ID, t.key).
		Scan(&lastNotified); err != nil {
		return err
	}
	if lastNotified != nil && now.Sub(*lastNotified) < time.Duration(r.ThrottleSeconds)*time.Second {
		return nil
	}
	return e.notify(ctx, tx, &a, r, "firing", now)
}

func lastN(ids []uuid.UUID, n int) []uuid.UUID {
	out := make([]uuid.UUID, 0, n)
	seen := map[uuid.UUID]bool{}
	for i := len(ids) - 1; i >= 0 && len(out) < n; i-- {
		if !seen[ids[i]] {
			seen[ids[i]] = true
			out = append(out, ids[i])
		}
	}
	slices.Reverse(out)
	return out
}

// resolve closes firing alerts whose window count fell below the threshold
// (or whose rule is gone or disabled), and sends one resolved notification
// for rules with auto_resolve.
func (e *Engine) resolve(ctx context.Context, tx pgx.Tx, org uuid.UUID, rules []Rule, now time.Time) error {
	rows, err := tx.Query(ctx,
		`SELECT id, rule_id, rule_name, dedupe_key, group_values, project_id, severity::text, first_at, last_at, count,
		        sample_event_ids
		 FROM alerts WHERE org_id = $1 AND state = 'firing' AND NOT test FOR UPDATE SKIP LOCKED`, org)
	if err != nil {
		return err
	}
	type firing struct {
		a    alertRow
		rule *uuid.UUID
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (firing, error) {
		var f firing
		var group []byte
		err := r.Scan(&f.a.ID, &f.rule, &f.a.RuleName, &f.a.Key, &group, &f.a.ProjectID, &f.a.Severity, &f.a.FirstAt,
			&f.a.LastAt, &f.a.Count, &f.a.Samples)
		_ = json.Unmarshal(group, &f.a.Group)
		f.a.OrgID = org
		return f, err
	})
	if err != nil {
		return err
	}
	byID := map[uuid.UUID]*Rule{}
	for i := range rules {
		byID[rules[i].ID] = &rules[i]
	}
	for _, f := range list {
		var r *Rule
		if f.rule != nil {
			r = byID[*f.rule]
		}
		if r != nil {
			n, _, _, err := e.windowCount(ctx, tx, r, f.a.Key, now)
			if err != nil {
				return err
			}
			if n >= r.Threshold {
				continue
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE alerts SET state = 'resolved', resolved_at = $2 WHERE id = $1`, f.a.ID, now); err != nil {
			return err
		}
		if r != nil && r.AutoResolve {
			a := f.a
			if err := e.notify(ctx, tx, &a, r, "resolved", now); err != nil {
				return err
			}
		}
	}
	return nil
}

// FireTest emits a synthetic alert.test event for rule and sends it through
// alert creation, recipient resolution and the outbox, bypassing the
// condition, threshold, throttle and quiet hours. It returns the alert id.
func (e *Engine) FireTest(ctx context.Context, org, ruleID, actor uuid.UUID) (uuid.UUID, error) {
	var alertID uuid.UUID
	err := tenant.WithOrg(ctx, e.DB, org, func(tx pgx.Tx) error {
		r, err := ScanRule(tx.QueryRow(ctx, `SELECT `+RuleColumns+` FROM alert_rules WHERE org_id = $1 AND id = $2`, org, ruleID))
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoRule
		}
		if err != nil {
			return err
		}
		now := e.now()
		ev := events.Event{ID: uuid.New(), OrgID: org, Type: events.AlertTest, Severity: r.Severity, OccurredAt: now,
			Attrs: map[string]any{"actor_id": actor.String(), "rule_id": r.ID.String()}}
		if err := events.InsertTx(ctx, tx, org, []events.Event{ev}); err != nil {
			return err
		}
		// Seen by this rule only: other rules on alert.test would fire again.
		if _, err := tx.Exec(ctx, `UPDATE events SET processed_at = $2 WHERE id = $1`, ev.ID, now); err != nil {
			return err
		}
		a := alertRow{OrgID: org, RuleName: r.Name, Key: "test:" + ev.ID.String(), Group: map[string]string{},
			Severity: r.Severity, FirstAt: now, LastAt: now, Count: 1, Samples: []uuid.UUID{ev.ID}, Test: true}
		if err := tx.QueryRow(ctx,
			`INSERT INTO alerts (org_id, rule_id, rule_name, dedupe_key, window_start, state, severity, first_at, last_at,
			                     count, sample_event_ids, test, resolved_at)
			 VALUES ($1, $2, $3, $4, $5, 'resolved', $6::alert_severity, $5, $5, 1, $7, true, $5) RETURNING id`,
			org, r.ID, r.Name, a.Key, now, r.Severity, a.Samples).Scan(&a.ID); err != nil {
			return err
		}
		alertID = a.ID
		test := r
		test.QuietHours = nil
		return e.notify(ctx, tx, &a, &test, "firing", now)
	})
	return alertID, err
}

// ErrNoRule means the rule does not exist in the org.
var ErrNoRule = errNoRule

// delivery is one outbox row to queue.
type delivery struct {
	kind      string
	channelID *uuid.UUID
	userID    *uuid.UUID
	target    string
}

// notify queues the notifications of one alert state change: in-app rows for
// every recipient, their personal channels, and the rule's shared channels.
func (e *Engine) notify(ctx context.Context, tx pgx.Tx, a *alertRow, r *Rule, state string, now time.Time) error {
	decision, sendAt := quietDecision(r.QuietHours, a.Severity, now)
	if decision == sendSuppress {
		_, err := tx.Exec(ctx, `UPDATE alerts SET suppressed = true WHERE id = $1`, a.ID)
		return err
	}
	var seq int
	q := `UPDATE alerts SET notify_seq = notify_seq + 1 WHERE id = $1 RETURNING notify_seq`
	if state == "firing" {
		q = `UPDATE alerts SET notify_seq = notify_seq + 1, last_notified_at = $2 WHERE id = $1 RETURNING notify_seq`
	}
	args := []any{a.ID}
	if state == "firing" {
		args = append(args, now)
	}
	if err := tx.QueryRow(ctx, q, args...).Scan(&seq); err != nil {
		return err
	}
	users, err := ResolveRecipients(ctx, tx, a.OrgID, r.Recipients)
	if err != nil {
		return err
	}
	var deliveries []delivery
	personal, err := e.personalChannels(ctx, tx, a.OrgID, users, a.Severity)
	if err != nil {
		return err
	}
	deliveries = append(deliveries, personal...)
	shared, err := sharedChannels(ctx, tx, a.OrgID, r.ChannelIDs)
	if err != nil {
		return err
	}
	deliveries = append(deliveries, shared...)

	// A runaway rule (threshold 1, no throttle, a flood of events) must not
	// fill the outbox: past MaxOutboxPerMinute rows a minute per org, only the
	// in-app notifications are written.
	var recent int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_outbox WHERE org_id = $1 AND created_at > $2`,
		a.OrgID, now.Add(-time.Minute)).Scan(&recent); err != nil {
		return err
	}
	if recent+len(deliveries) > MaxOutboxPerMinute {
		slog.Warn("alert deliveries over the per-org limit; only in-app notifications sent", "org", a.OrgID, "rule", r.ID)
		metrics.Deliveries.WithLabelValues("all", "limited").Add(float64(len(deliveries)))
		deliveries = nil
	}
	base, err := e.payload(ctx, tx, a, r, state)
	if err != nil {
		return err
	}
	// In-app notifications are always on for recipients.
	lang := e.Lang
	sum := channels.Render(&base, lang)
	for _, u := range users {
		if _, err := tx.Exec(ctx,
			`INSERT INTO notifications (org_id, user_id, alert_id, title, body, severity)
			 VALUES ($1, $2, $3, $4, $5, $6::alert_severity)`,
			a.OrgID, u, a.ID, capString(sum.Title, 300), capString(strings.Join(sum.Lines, "\n"), 2000), a.Severity); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, NotificationsChannel, u.String()); err != nil {
			return err
		}
	}
	for _, d := range deliveries {
		key := idempotencyKey(a.ID, seq, state, d)
		p := base
		p.EventID = key
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO notification_outbox (org_id, alert_id, rule_id, channel_kind, channel_id, user_id, target, payload,
			                                  next_attempt_at, idempotency_key)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (idempotency_key) DO NOTHING`,
			a.OrgID, a.ID, r.ID, d.kind, d.channelID, d.userID, capString(d.target, 320), raw, sendAt, key); err != nil {
			return err
		}
	}
	metrics.AlertsFired.WithLabelValues(state).Inc()
	_, err = tx.Exec(ctx, `SELECT pg_notify($1, $2)`, OutboxChannel, a.OrgID.String())
	return err
}

func idempotencyKey(alert uuid.UUID, seq int, state string, d delivery) string {
	var ch, user string
	if d.channelID != nil {
		ch = d.channelID.String()
	}
	if d.userID != nil {
		user = d.userID.String()
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%s|%s|%s", alert, seq, state, d.kind, ch, user)))
	return "gs1_" + hex.EncodeToString(sum[:20])
}

// ResolveRecipients returns user_ids ∪ members of group_ids ∪ members with a
// role in roles, keeping only current members of org whose account is
// enabled. tx must be scoped to org.
func ResolveRecipients(ctx context.Context, tx pgx.Tx, org uuid.UUID, rc Recipients) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT m.user_id FROM org_memberships m JOIN users u ON u.id = m.user_id AND u.disabled_at IS NULL
		 WHERE m.org_id = $1 AND (m.user_id = ANY($2) OR m.role::text = ANY($3)
		   OR m.user_id IN (SELECT g.user_id FROM user_group_members g WHERE g.org_id = $1 AND g.group_id = ANY($4)))
		 ORDER BY m.user_id`,
		org, nonNil(rc.UserIDs), nonNilS(rc.Roles), nonNil(rc.GroupIDs))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func nonNil(v []uuid.UUID) []uuid.UUID {
	if v == nil {
		return []uuid.UUID{}
	}
	return v
}

func nonNilS(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// Pref is one row of user_notification_prefs.
type Pref struct {
	ChannelKind string `json:"channel_kind"`
	Enabled     bool   `json:"enabled"`
	MinSeverity string `json:"min_severity"`
}

// PersonalKinds are the channel kinds a user can link.
var PersonalKinds = []string{channels.KindTelegram, channels.KindSlack, channels.KindEmail}

// DefaultPref is a user's setting for a kind without a row: on, from info.
func DefaultPref(kind string) Pref {
	return Pref{ChannelKind: kind, Enabled: true, MinSeverity: events.Info}
}

// personalChannels returns each user's linked channels that are on and
// whose minimum severity the alert reaches. Email uses the account address
// unless an email link sets another.
func (e *Engine) personalChannels(ctx context.Context, tx pgx.Tx, org uuid.UUID, users []uuid.UUID, severity string) ([]delivery, error) {
	if len(users) == 0 {
		return nil, nil
	}
	type addr struct{ telegram, slack, email string }
	addrs := map[uuid.UUID]*addr{}
	rows, err := tx.Query(ctx,
		`SELECT u.id, u.email, l.kind, l.address FROM users u
		 LEFT JOIN user_channel_links l ON l.user_id = u.id AND l.verified_at IS NOT NULL
		 WHERE u.id = ANY($1)`, users)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		var email string
		var kind, address *string
		if err := rows.Scan(&id, &email, &kind, &address); err != nil {
			rows.Close()
			return nil, err
		}
		a := addrs[id]
		if a == nil {
			a = &addr{email: email}
			addrs[id] = a
		}
		if kind == nil || address == nil {
			continue
		}
		switch *kind {
		case channels.KindTelegram:
			a.telegram = *address
		case channels.KindSlack:
			a.slack = *address
		case channels.KindEmail:
			a.email = *address
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	prefs := map[string]Pref{}
	prows, err := tx.Query(ctx,
		`SELECT user_id, channel_kind, enabled, min_severity::text FROM user_notification_prefs
		 WHERE org_id = $1 AND user_id = ANY($2)`, org, users)
	if err != nil {
		return nil, err
	}
	for prows.Next() {
		var id uuid.UUID
		var p Pref
		if err := prows.Scan(&id, &p.ChannelKind, &p.Enabled, &p.MinSeverity); err != nil {
			prows.Close()
			return nil, err
		}
		prefs[id.String()+p.ChannelKind] = p
	}
	prows.Close()
	if err := prows.Err(); err != nil {
		return nil, err
	}
	var out []delivery
	for _, u := range users {
		a := addrs[u]
		if a == nil {
			continue
		}
		for _, kind := range PersonalKinds {
			var target string
			var capable bool
			switch kind {
			case channels.KindTelegram:
				target, capable = a.telegram, e.Caps.Telegram
			case channels.KindSlack:
				target, capable = a.slack, e.Caps.Slack
			case channels.KindEmail:
				target, capable = a.email, e.Caps.SMTP
			}
			if target == "" || !capable {
				continue
			}
			p, ok := prefs[u.String()+kind]
			if !ok {
				p = DefaultPref(kind)
			}
			if !p.Enabled || !AtLeast(severity, p.MinSeverity) {
				continue
			}
			uid := u
			out = append(out, delivery{kind: kind, userID: &uid, target: target})
		}
	}
	return out, nil
}

// sharedChannels returns the enabled org channels among ids.
func sharedChannels(ctx context.Context, tx pgx.Tx, org uuid.UUID, ids []uuid.UUID) ([]delivery, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx,
		`SELECT id, kind, config FROM notification_channels WHERE org_id = $1 AND id = ANY($2) AND enabled ORDER BY id`, org, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (delivery, error) {
		var id uuid.UUID
		var kind string
		var raw []byte
		if err := r.Scan(&id, &kind, &raw); err != nil {
			return delivery{}, err
		}
		var cfg map[string]any
		_ = json.Unmarshal(raw, &cfg)
		return delivery{kind: kind, channelID: &id, target: ChannelTarget(kind, cfg)}, nil
	})
}

// ChannelTarget is the address of a shared channel that may be shown: never
// a secret, a URL path or a query.
func ChannelTarget(kind string, cfg map[string]any) string {
	s := func(k string) string { v, _ := cfg[k].(string); return v }
	switch kind {
	case channels.KindTelegram:
		return s("chat_id")
	case channels.KindSlack:
		if s("mode") == "webhook" {
			return "incoming webhook"
		}
		return s("channel")
	case channels.KindTeams:
		return "workflow"
	case channels.KindWebhook:
		return channels.RedactURL(s("url"))
	case channels.KindA2A:
		return channels.RedactURL(s("agent_card_url"))
	case channels.KindEmail:
		var to []string
		if list, ok := cfg["to"].([]any); ok {
			for _, v := range list {
				if x, ok := v.(string); ok {
					to = append(to, x)
				}
			}
		}
		return capString(strings.Join(to, ", "), 320)
	}
	return ""
}

// payload builds the webhook payload v1 of an alert (EventID set per row).
func (e *Engine) payload(ctx context.Context, tx pgx.Tx, a *alertRow, r *Rule, state string) (channels.Payload, error) {
	p := channels.Payload{
		Schema: channels.SchemaV1, AlertID: a.ID.String(), Rule: channels.RuleRef{ID: r.ID.String(), Name: r.Name},
		State: state, Severity: a.Severity, OrgID: a.OrgID.String(), Count: a.Count, WindowSeconds: r.WindowSeconds,
		FirstAt: a.FirstAt.UTC(), LastAt: a.LastAt.UTC(), Group: a.Group, Samples: []channels.Sample{}, Test: a.Test,
	}
	if p.Group == nil {
		p.Group = map[string]string{}
	}
	if a.ProjectID != nil {
		s := a.ProjectID.String()
		p.ProjectID = &s
	}
	if len(a.Samples) > 0 {
		rows, err := tx.Query(ctx,
			`SELECT id, type, occurred_at, attrs FROM events WHERE org_id = $1 AND id = ANY($2) ORDER BY occurred_at DESC, id LIMIT 10`,
			a.OrgID, a.Samples)
		if err != nil {
			return p, err
		}
		for rows.Next() {
			var s channels.Sample
			var id uuid.UUID
			var raw []byte
			if err := rows.Scan(&id, &s.Type, &s.OccurredAt, &raw); err != nil {
				rows.Close()
				return p, err
			}
			var attrs map[string]any
			_ = json.Unmarshal(raw, &attrs)
			s.EventID, s.OccurredAt, s.Attrs = id.String(), s.OccurredAt.UTC(), SafeAttrs(attrs)
			p.Samples = append(p.Samples, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return p, err
		}
	}
	base := strings.TrimRight(e.PublicURL, "/")
	p.Links.Alert = base + "/ui/alerts/history?id=" + url.QueryEscape(a.ID.String())
	req := base + "/ui/requests"
	for _, s := range p.Samples {
		if id, _ := s.Attrs["request_id"].(string); id != "" {
			req += "?q=" + url.QueryEscape(id)
			break
		}
	}
	p.Links.Requests = req
	return p, nil
}
