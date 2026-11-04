// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"time"

	"github.com/giaplee/guard-spec/internal/alerts/channels"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DefaultEmailDailyCap is the emails one org may send per 24 hours unless
// ALERTS_EMAIL_DAILY_CAP says otherwise. The instance's SMTP account is
// shared by every org, and any user can create one.
const DefaultEmailDailyCap = 500

// ConfirmedAddresses lists the confirmed addresses of an email channel.
func ConfirmedAddresses(ctx context.Context, tx pgx.Tx, org, channel uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx,
		`SELECT address FROM channel_email_addresses WHERE org_id = $1 AND channel_id = $2 AND confirmed_at IS NOT NULL
		 ORDER BY address`, org, channel)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// EmailsSentToday counts the org's emails of the last 24 hours: deliveries
// sent or being sent, and confirmation mails.
func EmailsSentToday(ctx context.Context, tx pgx.Tx, org uuid.UUID, now time.Time) (int, error) {
	var n int
	err := tx.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM notification_outbox WHERE org_id = $1 AND channel_kind = 'email'
		           AND state IN ('sent', 'sending') AND created_at > $2)
		      + (SELECT count(*) FROM channel_email_addresses WHERE org_id = $1 AND sent_at > $2)`,
		org, now.Add(-24*time.Hour)).Scan(&n)
	return n, err
}

func (d *Dispatcher) emailCap() int {
	if d.EmailDailyCap > 0 {
		return d.EmailDailyCap
	}
	return DefaultEmailDailyCap
}

// checkEmailCap refuses an email once the org reached its daily cap. The row
// being sent is already "sending", so it counts.
func (d *Dispatcher) checkEmailCap(ctx context.Context, org uuid.UUID) error {
	var n int
	err := tenant.WithOrg(ctx, d.DB, org, func(tx pgx.Tx) error {
		var err error
		n, err = EmailsSentToday(ctx, tx, org, d.now())
		return err
	})
	if err != nil {
		return err
	}
	if n > d.emailCap() {
		return &channels.Error{Permanent: true, Msg: "the organization reached its daily email limit"}
	}
	return nil
}

func toAny(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}
