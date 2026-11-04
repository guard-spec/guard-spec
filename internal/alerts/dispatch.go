// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/giaplee/guard-spec/internal/alerts/channels"
	"github.com/giaplee/guard-spec/internal/metrics"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Backoff is the wait after each failed attempt; the attempt after the last
// one is final, and a failure there moves the row to dead.
var Backoff = []time.Duration{2 * time.Second, 10 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute}

// MaxAttempts is how many times a delivery is tried.
const MaxAttempts = 6

const (
	claimBatch  = 20
	claimLease  = 60 * time.Second // a claimed row returns to the queue if its replica dies
	parallelism = 8
)

// SecretEnvRe and the prefixes are the allowlist of secret_env names.
var SecretEnvRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

// SecretEnvPrefixes are the variable name prefixes a channel may name.
var SecretEnvPrefixes = []string{"GUARDSPEC_ALERT_", "TELEGRAM_BOT_TOKEN_", "SLACK_", "TEAMS_", "WEBHOOK_SECRET_", "A2A_"}

// AllowedSecretEnv reports whether a channel may read the variable name.
func AllowedSecretEnv(name string) bool {
	if !SecretEnvRe.MatchString(name) {
		return false
	}
	for _, p := range SecretEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Instance variables of personal channels.
const (
	EnvTelegramToken = "TELEGRAM_BOT_TOKEN"
	EnvSlackToken    = "SLACK_BOT_TOKEN"
)

// Dispatcher delivers outbox rows.
type Dispatcher struct {
	DB      *pgxpool.Pool
	Senders map[string]channels.Sender
	Getenv  func(string) string
	// The instance bot tokens of personal channels (TELEGRAM_BOT_TOKEN,
	// SLACK_BOT_TOKEN).
	TelegramToken, SlackToken string
	// SecretOrgs is ALERTS_SECRET_ORGS.
	SecretOrgs SecretOrgs
	// EmailDailyCap bounds the emails an org sends per 24 hours
	// (ALERTS_EMAIL_DAILY_CAP), confirmation mails included. 0: DefaultEmailDailyCap.
	EmailDailyCap int
	Lang          string
	Now           func() time.Time
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// outboxRow is a claimed delivery.
type outboxRow struct {
	ID        uuid.UUID
	Kind      string
	ChannelID *uuid.UUID
	UserID    *uuid.UUID
	Target    string
	Payload   channels.Payload
	Attempts  int
	Key       string
	channel   *ChannelRow
}

// ChannelRow is a row of notification_channels.
type ChannelRow struct {
	ID        uuid.UUID      `json:"id"`
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	Config    map[string]any `json:"config"`
	SecretEnv *string        `json:"secret_env"`
	Enabled   bool           `json:"enabled"`
	// VerifiedAt is set when /link verified the chat of a Telegram channel
	// on the instance bot.
	VerifiedAt *time.Time `json:"verified_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	// confirmed are the confirmed addresses of an email channel (claim).
	confirmed []string
}

// ChannelColumns are the columns ScanChannel reads.
const ChannelColumns = `id, name, kind, config, secret_env, enabled, verified_at, created_at, updated_at`

// ScanChannel reads a row of ChannelColumns.
func ScanChannel(row pgx.Row) (ChannelRow, error) {
	var c ChannelRow
	var raw []byte
	if err := row.Scan(&c.ID, &c.Name, &c.Kind, &raw, &c.SecretEnv, &c.Enabled, &c.VerifiedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return c, err
	}
	if err := json.Unmarshal(raw, &c.Config); err != nil || c.Config == nil {
		c.Config = map[string]any{}
	}
	return c, nil
}

// DispatchOrg claims and delivers the org's due rows, up to a few batches.
// It returns how many it attempted.
func (d *Dispatcher) DispatchOrg(ctx context.Context, org uuid.UUID) (int, error) {
	total := 0
	for i := 0; i < 5; i++ {
		rows, err := d.claim(ctx, org)
		if err != nil {
			return total, err
		}
		if len(rows) == 0 {
			return total, nil
		}
		total += len(rows)
		sem := make(chan struct{}, parallelism)
		var wg sync.WaitGroup
		for i := range rows {
			wg.Add(1)
			sem <- struct{}{}
			go func(r *outboxRow) {
				defer wg.Done()
				defer func() { <-sem }()
				d.deliver(ctx, org, r)
			}(&rows[i])
		}
		wg.Wait()
		if len(rows) < claimBatch {
			return total, nil
		}
	}
	return total, nil
}

// claim moves due rows to sending with a lease and attempts+1. Rows of
// users who left the org, and of channels that were deleted or disabled,
// go to dead instead.
func (d *Dispatcher) claim(ctx context.Context, org uuid.UUID) ([]outboxRow, error) {
	var out []outboxRow
	now := d.now()
	err := tenant.WithOrg(ctx, d.DB, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE notification_outbox o SET state = 'dead', last_error = 'the recipient is no longer a member of the organization'
			 WHERE o.org_id = $1 AND o.state IN ('pending', 'failed', 'sending') AND o.user_id IS NOT NULL
			   AND NOT EXISTS (SELECT 1 FROM org_memberships m WHERE m.org_id = $1 AND m.user_id = o.user_id)`, org); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE notification_outbox o SET state = 'dead', last_error = 'the channel was deleted or disabled'
			 WHERE o.org_id = $1 AND o.state IN ('pending', 'failed', 'sending') AND o.user_id IS NULL
			   AND NOT EXISTS (SELECT 1 FROM notification_channels c WHERE c.id = o.channel_id AND c.enabled)`, org); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`UPDATE notification_outbox SET state = 'sending', attempts = attempts + 1, next_attempt_at = $3
			 WHERE id IN (SELECT id FROM notification_outbox
			              WHERE org_id = $1 AND state IN ('pending', 'failed', 'sending') AND next_attempt_at <= $2
			              ORDER BY next_attempt_at LIMIT $4 FOR UPDATE SKIP LOCKED)
			 RETURNING id, channel_kind, channel_id, user_id, target, payload, attempts, idempotency_key`,
			org, now, now.Add(claimLease), claimBatch)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (outboxRow, error) {
			var o outboxRow
			var raw []byte
			err := r.Scan(&o.ID, &o.Kind, &o.ChannelID, &o.UserID, &o.Target, &raw, &o.Attempts, &o.Key)
			if err == nil {
				err = json.Unmarshal(raw, &o.Payload)
			}
			return o, err
		})
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for _, o := range out {
			if o.ChannelID != nil {
				ids = append(ids, *o.ChannelID)
			}
		}
		if len(ids) == 0 {
			return nil
		}
		crows, err := tx.Query(ctx, `SELECT `+ChannelColumns+` FROM notification_channels WHERE org_id = $1 AND id = ANY($2)`, org, ids)
		if err != nil {
			return err
		}
		chans, err := pgx.CollectRows(crows, func(r pgx.CollectableRow) (ChannelRow, error) { return ScanChannel(r) })
		if err != nil {
			return err
		}
		for j := range chans {
			if chans[j].Kind == channels.KindEmail {
				if chans[j].confirmed, err = ConfirmedAddresses(ctx, tx, org, chans[j].ID); err != nil {
					return err
				}
			}
		}
		for i := range out {
			for j := range chans {
				if out[i].ChannelID != nil && chans[j].ID == *out[i].ChannelID {
					out[i].channel = &chans[j]
				}
			}
		}
		return nil
	})
	return out, err
}

// Message builds the message of a shared channel or a personal delivery.
func (d *Dispatcher) message(org uuid.UUID, r *outboxRow) (*channels.Message, error) {
	m := &channels.Message{Kind: r.Kind, Payload: r.Payload, IdempotencyKey: r.Key, Lang: d.Lang}
	getenv := d.Getenv
	if r.channel != nil {
		m.Config = r.channel.Config
		if r.channel.SecretEnv != nil && *r.channel.SecretEnv != "" {
			if err := CheckSecretEnv(r.Kind, *r.channel.SecretEnv, org, d.SecretOrgs); err != nil {
				return nil, &channels.Error{Permanent: true, Msg: err.Error()}
			}
			m.Secret = getenv(*r.channel.SecretEnv)
			if m.Secret == "" {
				return nil, &channels.Error{Permanent: true, Msg: "the variable " + *r.channel.SecretEnv + " is not set"}
			}
		}
		switch r.Kind {
		case channels.KindTelegram:
			if m.Secret == "" {
				// The instance bot posts only to a chat that sent /link.
				if r.channel.VerifiedAt == nil {
					return nil, &channels.Error{Permanent: true,
						Msg: "the Telegram chat is not verified: send the /link code in the chat"}
				}
				m.Secret = d.TelegramToken
			}
		case channels.KindEmail:
			// Only addresses that confirmed (double opt-in).
			if len(r.channel.confirmed) == 0 {
				return nil, &channels.Error{Permanent: true, Msg: "no confirmed address"}
			}
			cfg := map[string]any{"to": toAny(r.channel.confirmed)}
			if l, ok := r.channel.Config["lang"]; ok {
				cfg["lang"] = l
			}
			m.Config = cfg
		}
		return m, nil
	}
	m.Target = r.Target
	switch r.Kind {
	case channels.KindTelegram:
		m.Secret = d.TelegramToken
	case channels.KindSlack:
		m.Secret = d.SlackToken
		m.Config = map[string]any{"mode": "bot"}
	}
	return m, nil
}

// Send delivers one message with the sender of its kind.
func (d *Dispatcher) Send(ctx context.Context, m *channels.Message) (channels.Result, error) {
	s, ok := d.Senders[m.Kind]
	if !ok {
		return channels.Result{}, &channels.Error{Permanent: true, Msg: "no sender for " + m.Kind}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*channels.Timeout)
	defer cancel()
	return s.Send(ctx, m)
}

// TestChannel sends a test alert to a shared channel synchronously.
func (d *Dispatcher) TestChannel(ctx context.Context, org uuid.UUID, c *ChannelRow, p channels.Payload) (channels.Result, error) {
	if c.Kind == channels.KindEmail {
		err := tenant.WithOrg(ctx, d.DB, org, func(tx pgx.Tx) error {
			var err error
			c.confirmed, err = ConfirmedAddresses(ctx, tx, org, c.ID)
			return err
		})
		if err != nil {
			return channels.Result{}, err
		}
	}
	m, err := d.message(org, &outboxRow{Kind: c.Kind, ChannelID: &c.ID, Payload: p, Key: p.EventID, channel: c})
	if err != nil {
		return channels.Result{}, err
	}
	if c.Kind == channels.KindEmail {
		if err := d.checkEmailCap(ctx, org); err != nil {
			return channels.Result{}, err
		}
	}
	return d.Send(ctx, m)
}

func (d *Dispatcher) deliver(ctx context.Context, org uuid.UUID, r *outboxRow) {
	if r.Attempts == 1 && !r.Payload.LastAt.IsZero() {
		metrics.DeliveryLatency.WithLabelValues(r.Kind).Observe(d.now().Sub(r.Payload.LastAt).Seconds())
	}
	var res channels.Result
	m, err := d.message(org, r)
	if err == nil && r.Kind == channels.KindEmail {
		err = d.checkEmailCap(ctx, org)
	}
	if err == nil {
		res, err = d.Send(ctx, m)
	}
	secret := ""
	if m != nil {
		secret = m.Secret
	}
	now := d.now()
	var q string
	var args []any
	if err == nil {
		metrics.Deliveries.WithLabelValues(r.Kind, "sent").Inc()
		q = `UPDATE notification_outbox SET state = 'sent', sent_at = $2, last_status = $3, remote_id = NULLIF($4, ''),
		        last_error = NULL WHERE id = $1`
		args = []any{r.ID, now, res.Status, res.RemoteID}
	} else {
		ce := channels.AsError(err, secret)
		msg := channels.Redact(ce.Msg, secret)
		state, next := "failed", now
		if ce.Permanent || r.Attempts >= MaxAttempts {
			state = "dead"
			metrics.Deliveries.WithLabelValues(r.Kind, "dead").Inc()
		} else {
			metrics.Deliveries.WithLabelValues(r.Kind, "retry").Inc()
			wait := Backoff[min(r.Attempts-1, len(Backoff)-1)]
			if ce.Status == 429 && ce.RetryAfter > 0 {
				wait = ce.RetryAfter
			}
			next = now.Add(wait)
		}
		var status *int
		if ce.Status != 0 {
			status = &ce.Status
		}
		q = `UPDATE notification_outbox SET state = $2, next_attempt_at = $3, last_error = $4, last_status = $5 WHERE id = $1`
		args = []any{r.ID, state, next, msg, status}
		slog.Info("alert delivery failed", "org", org, "kind", r.Kind, "attempt", r.Attempts, "state", state, "err", msg)
	}
	// The result is written even when ctx was cancelled (shutdown).
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if werr := tenant.WithOrg(wctx, d.DB, org, func(tx pgx.Tx) error {
		_, err := tx.Exec(wctx, q, args...)
		return err
	}); werr != nil && !errors.Is(werr, context.Canceled) {
		slog.Warn("alert delivery result not saved", "org", org, "err", werr)
	}
}
