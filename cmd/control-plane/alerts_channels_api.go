// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/alerts"
	"github.com/guard-spec/guard-spec/internal/alerts/channels"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
)

// Channel CRUD, the /link verification of Telegram channels on the instance
// bot, and the double opt-in of shared email addresses.

// EmailConfirmTTL is how long a shared-mailbox confirmation link works.
const EmailConfirmTTL = 7 * 24 * time.Hour

// ChannelLinkTTL is how long a Telegram /link code works.
const ChannelLinkTTL = 10 * time.Minute

func randomCode(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// loadAddresses returns the addresses of the email channels among ids.
func loadAddresses(ctx context.Context, tx pgx.Tx, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID][]emailAddress, error) {
	out := map[uuid.UUID][]emailAddress{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx,
		`SELECT channel_id, address, confirmed_at, sent_at FROM channel_email_addresses
		 WHERE org_id = $1 AND channel_id = ANY($2) ORDER BY address`, org, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var a emailAddress
		if err := rows.Scan(&id, &a.Address, &a.ConfirmedAt, &a.SentAt); err != nil {
			return nil, err
		}
		a.Confirmed = a.ConfirmedAt != nil
		out[id] = append(out[id], a)
	}
	return out, rows.Err()
}

func configTo(ch *alerts.ChannelRow) []string {
	var out []string
	if list, ok := ch.Config["to"].([]any); ok {
		for _, v := range list {
			if s, ok := v.(string); ok {
				out = append(out, strings.ToLower(s))
			}
		}
	}
	return out
}

// pendingMail is a confirmation mail to send after the transaction.
type pendingMail struct {
	address, token string
}

// syncAddresses makes channel_email_addresses match config.to: removed
// addresses go, new ones are added unconfirmed with a fresh token. It
// returns the mails to send, within the org's daily email cap.
func (rt *alertsRuntime) syncAddresses(ctx context.Context, tx pgx.Tx, org uuid.UUID, ch *alerts.ChannelRow) ([]pendingMail, error) {
	to := configTo(ch)
	if _, err := tx.Exec(ctx, `DELETE FROM channel_email_addresses WHERE org_id = $1 AND channel_id = $2 AND NOT (address = ANY($3))`,
		org, ch.ID, to); err != nil {
		return nil, err
	}
	existing, err := loadAddresses(ctx, tx, org, []uuid.UUID{ch.ID})
	if err != nil {
		return nil, err
	}
	var fresh []string
	for _, a := range to {
		if !slices.ContainsFunc(existing[ch.ID], func(e emailAddress) bool { return e.Address == a }) {
			fresh = append(fresh, a)
		}
	}
	return rt.issueConfirmations(ctx, tx, org, ch.ID, fresh)
}

// issueConfirmations stores a new token for each address and returns the
// mails to send. Addresses past the daily cap get no mail (resend later).
func (rt *alertsRuntime) issueConfirmations(ctx context.Context, tx pgx.Tx, org, channel uuid.UUID, addrs []string) ([]pendingMail, error) {
	if len(addrs) == 0 || !rt.cfg.smtp.Enabled() {
		for _, a := range addrs {
			if _, err := tx.Exec(ctx, `INSERT INTO channel_email_addresses (org_id, channel_id, address) VALUES ($1, $2, $3)
				ON CONFLICT DO NOTHING`, org, channel, a); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	sent, err := alerts.EmailsSentToday(ctx, tx, org, time.Now())
	if err != nil {
		return nil, err
	}
	var mails []pendingMail
	for _, a := range addrs {
		if sent >= rt.cfg.emailDailyCap {
			if _, err := tx.Exec(ctx, `INSERT INTO channel_email_addresses (org_id, channel_id, address) VALUES ($1, $2, $3)
				ON CONFLICT DO NOTHING`, org, channel, a); err != nil {
				return nil, err
			}
			continue
		}
		token, err := randomCode(24)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO channel_email_addresses (org_id, channel_id, address, token_hash, expires_at, sent_at)
			 VALUES ($1, $2, $3, $4, $5, NOW())
			 ON CONFLICT (channel_id, address) DO UPDATE SET token_hash = EXCLUDED.token_hash,
			   expires_at = EXCLUDED.expires_at, sent_at = NOW()
			 WHERE channel_email_addresses.confirmed_at IS NULL`,
			org, channel, a, hashCode(token), time.Now().Add(EmailConfirmTTL)); err != nil {
			return nil, err
		}
		sent++
		mails = append(mails, pendingMail{address: a, token: token})
	}
	return mails, nil
}

// sendConfirmations mails the links, after the transaction committed.
func (rt *alertsRuntime) sendConfirmations(orgName string, mails []pendingMail) {
	if len(mails) == 0 {
		return
	}
	email := &channels.Email{SMTP: rt.cfg.smtp}
	base := strings.TrimRight(rt.publicURL, "/")
	go func() {
		for _, m := range mails {
			ctx, cancel := context.WithTimeout(rt.base, 2*channels.Timeout)
			subject, body := confirmMail(rt.cfg.lang, orgName, base+"/v1/integrations/email/confirm?token="+m.token)
			if err := email.SendText(ctx, m.address, subject, body); err != nil {
				slog.Warn("email confirmation not sent", "err", err)
			}
			cancel()
		}
	}()
}

func confirmMail(lang, org, link string) (string, string) {
	if lang == "vi" {
		return "[Guard Spec] Xác nhận nhận cảnh báo",
			"Tổ chức \"" + org + "\" muốn gửi cảnh báo bảo mật của Guard Spec tới địa chỉ này.\n\n" +
				"Mở liên kết sau để đồng ý (hết hạn sau 7 ngày):\n" + link + "\n\n" +
				"Nếu bạn không muốn nhận, hãy bỏ qua thư này: không có gì được gửi tới khi bạn xác nhận.\n"
	}
	return "[Guard Spec] Confirm alert notifications",
		"The organization \"" + org + "\" wants to send Guard Spec security alerts to this address.\n\n" +
			"Open this link to agree (it expires in 7 days):\n" + link + "\n\n" +
			"If you do not want them, ignore this mail: nothing is sent until you confirm.\n"
}

func orgName(ctx context.Context, tx pgx.Tx, org uuid.UUID) string {
	var name string
	_ = tx.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, org).Scan(&name)
	return name
}

func (rt *alertsRuntime) listChannels(c *fiber.Ctx) error {
	org := orgID(c)
	pg, err := parsePage(c, false)
	if err != nil {
		return badPage(c, err)
	}
	ks := keyset{sort: "created_at", id: "id", desc: true}
	var list []alerts.ChannelRow
	var total int64
	var addrs map[uuid.UUID][]emailAddress
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		args := []any{org}
		filter := ""
		if k := c.Query("kind"); k != "" {
			args = append(args, k)
			filter = fmt.Sprintf(" AND kind = $%d", len(args))
		}
		if err := tx.QueryRow(c.Context(), `SELECT count(*) FROM notification_channels WHERE org_id = $1`+filter, args...).
			Scan(&total); err != nil {
			return err
		}
		cond, args, err := ks.where(pg, args)
		if err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(), `SELECT `+alerts.ChannelColumns+` FROM notification_channels WHERE org_id = $1`+
			filter+cond+ks.orderLimit(pg), args...)
		if err != nil {
			return err
		}
		if list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (alerts.ChannelRow, error) { return alerts.ScanChannel(r) }); err != nil {
			return err
		}
		var ids []uuid.UUID
		for _, ch := range list {
			ids = append(ids, ch.ID)
		}
		addrs, err = loadAddresses(c.Context(), tx, org, ids)
		return err
	})
	if err != nil {
		return channelError(c, err)
	}
	list, next := page(list, pg.Limit, func(r alerts.ChannelRow) pageCursor { return timeCursor(r.CreatedAt, r.ID.String()) })
	items := make([]channelView, 0, len(list))
	for _, ch := range list {
		items = append(items, rt.view(org, ch, addrs[ch.ID]))
	}
	return envelope(c, items, next, total, false)
}

func (rt *alertsRuntime) loadChannel(c *fiber.Ctx, org uuid.UUID, _ bool) (alerts.ChannelRow, error) {
	id, err := idParam(c)
	if err != nil {
		return alerts.ChannelRow{}, pgx.ErrNoRows
	}
	var ch alerts.ChannelRow
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		ch, err = alerts.ScanChannel(tx.QueryRow(c.Context(),
			`SELECT `+alerts.ChannelColumns+` FROM notification_channels WHERE org_id = $1 AND id = $2`, org, id))
		return err
	})
	return ch, err
}

// channelJSON loads the channel's addresses and writes its view.
func (rt *alertsRuntime) channelJSON(c *fiber.Ctx, org uuid.UUID, ch alerts.ChannelRow, status int) error {
	var addrs map[uuid.UUID][]emailAddress
	err := tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		var err error
		addrs, err = loadAddresses(c.Context(), tx, org, []uuid.UUID{ch.ID})
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	return c.Status(status).JSON(rt.view(org, ch, addrs[ch.ID]))
}

func (rt *alertsRuntime) getChannel(c *fiber.Ctx) error {
	org := orgID(c)
	ch, err := rt.loadChannel(c, org, false)
	if err != nil {
		return channelError(c, err)
	}
	return rt.channelJSON(c, org, ch, 200)
}

type channelInput struct {
	Name      *string         `json:"name"`
	Kind      *string         `json:"kind"`
	Config    *map[string]any `json:"config"`
	SecretEnv json.RawMessage `json:"secret_env"`
	Enabled   *bool           `json:"enabled"`
}

func (in *channelInput) apply(ch *alerts.ChannelRow) error {
	if in.Name != nil {
		ch.Name = *in.Name
	}
	if in.Config != nil {
		ch.Config = *in.Config
	}
	if in.Enabled != nil {
		ch.Enabled = *in.Enabled
	}
	if len(in.SecretEnv) > 0 {
		if string(in.SecretEnv) == "null" {
			ch.SecretEnv = nil
		} else {
			var s string
			if err := json.Unmarshal(in.SecretEnv, &s); err != nil {
				return errors.New("secret_env must be a variable name or null")
			}
			ch.SecretEnv = &s
		}
	}
	return nil
}

// normalizeEmailConfig lower-cases config.to, so addresses compare.
func normalizeEmailConfig(ch *alerts.ChannelRow) {
	if ch.Kind != channels.KindEmail {
		return
	}
	if list, ok := ch.Config["to"].([]any); ok {
		for i, v := range list {
			if s, ok := v.(string); ok {
				list[i] = strings.ToLower(s)
			}
		}
	}
}

func (rt *alertsRuntime) createChannel(c *fiber.Ctx) error {
	org := orgID(c)
	var in channelInput
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	if in.Kind == nil {
		return badRequest(c, "kind is required")
	}
	ch := alerts.ChannelRow{ID: uuid.New(), Kind: *in.Kind, Enabled: true}
	if err := in.apply(&ch); err != nil {
		return badRequest(c, err.Error())
	}
	if err := rt.validateChannel(org, &ch, nil); err != nil {
		return badRequest(c, err.Error())
	}
	normalizeEmailConfig(&ch)
	cfg, _ := json.Marshal(ch.Config)
	var mails []pendingMail
	var name string
	err := tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if err := tx.QueryRow(c.Context(),
			`INSERT INTO notification_channels (id, org_id, name, kind, config, secret_env, enabled)
			 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING created_at, updated_at`,
			ch.ID, org, ch.Name, ch.Kind, cfg, ch.SecretEnv, ch.Enabled).Scan(&ch.CreatedAt, &ch.UpdatedAt); err != nil {
			return err
		}
		if ch.Kind == channels.KindEmail {
			var err error
			name = orgName(c.Context(), tx, org)
			mails, err = rt.syncAddresses(c.Context(), tx, org, &ch)
			return err
		}
		return nil
	})
	if err != nil {
		return channelError(c, err)
	}
	rt.sendConfirmations(name, mails)
	logActivity(c, rt.db, &org, "alerts.channel.created", ch.Name, map[string]any{"id": ch.ID, "kind": ch.Kind})
	return rt.channelJSON(c, org, ch, 201)
}

func (rt *alertsRuntime) updateChannel(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var in channelInput
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	var ch alerts.ChannelRow
	var invalid error
	var mails []pendingMail
	var name string
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if ch, err = alerts.ScanChannel(tx.QueryRow(c.Context(),
			`SELECT `+alerts.ChannelColumns+` FROM notification_channels WHERE org_id = $1 AND id = $2 FOR UPDATE`, org, id)); err != nil {
			return err
		}
		prev := ch
		prev.Config = map[string]any{}
		for k, v := range ch.Config {
			prev.Config[k] = v
		}
		if in.Kind != nil && *in.Kind != ch.Kind {
			invalid = errors.New("kind cannot be changed; create a new channel")
			return nil
		}
		if invalid = in.apply(&ch); invalid != nil {
			return nil
		}
		if ch.Kind == channels.KindTelegram && ch.SecretEnv == nil && in.Config != nil {
			// The verified chat stays unless the client names another.
			if _, named := ch.Config["chat_id"]; !named && configChat(&prev) != "" && prev.SecretEnv == nil {
				ch.Config["chat_id"] = configChat(&prev)
			}
		}
		if invalid = rt.validateChannel(org, &ch, &prev); invalid != nil {
			return nil
		}
		normalizeEmailConfig(&ch)
		// A Telegram channel that changes bot loses its verification.
		reset := ch.Kind == channels.KindTelegram && !sameSecretEnv(prev.SecretEnv, ch.SecretEnv)
		cfg, _ := json.Marshal(ch.Config)
		if err := tx.QueryRow(c.Context(),
			`UPDATE notification_channels SET name = $3, config = $4, secret_env = $5, enabled = $6, updated_at = NOW(),
			   verified_at = CASE WHEN $7 THEN NULL ELSE verified_at END
			 WHERE org_id = $1 AND id = $2 RETURNING updated_at, verified_at`,
			org, id, ch.Name, cfg, ch.SecretEnv, ch.Enabled, reset).Scan(&ch.UpdatedAt, &ch.VerifiedAt); err != nil {
			return err
		}
		if ch.Kind == channels.KindEmail {
			name = orgName(c.Context(), tx, org)
			mails, err = rt.syncAddresses(c.Context(), tx, org, &ch)
			return err
		}
		return nil
	})
	if invalid != nil {
		return badRequest(c, invalid.Error())
	}
	if err != nil {
		return channelError(c, err)
	}
	rt.sendConfirmations(name, mails)
	logActivity(c, rt.db, &org, "alerts.channel.updated", ch.Name, map[string]any{"id": ch.ID, "enabled": ch.Enabled})
	return rt.channelJSON(c, org, ch, 200)
}

func sameSecretEnv(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (rt *alertsRuntime) deleteChannel(c *fiber.Ctx) error {
	org := orgID(c)
	id, err := idParam(c)
	if err != nil {
		return notFound(c)
	}
	var name string
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if err := tx.QueryRow(c.Context(), `DELETE FROM notification_channels WHERE org_id = $1 AND id = $2 RETURNING name`,
			org, id).Scan(&name); err != nil {
			return err
		}
		_, err := tx.Exec(c.Context(), `UPDATE alert_rules SET channel_ids = array_remove(channel_ids, $2)
			WHERE org_id = $1 AND $2 = ANY(channel_ids)`, org, id)
		return err
	})
	if err != nil {
		return channelError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.channel.deleted", name, map[string]any{"id": id})
	return c.SendStatus(204)
}

// telegramChannelLink issues the one-time /link code of a Telegram channel on
// the instance bot. Sending "/link <code>" in the chat (a group the bot was
// added to) sets the channel's chat_id and verifies it.
func (rt *alertsRuntime) telegramChannelLink(c *fiber.Ctx) error {
	org := orgID(c)
	ch, err := rt.loadChannel(c, org, false)
	if err != nil {
		return channelError(c, err)
	}
	if ch.Kind != channels.KindTelegram || ch.SecretEnv != nil {
		return badRequest(c, "only Telegram channels on the instance bot are verified with /link")
	}
	if rt.cfg.telegramToken == "" || rt.bot() == "" || (rt.cfg.telegramSecret == "" && !rt.cfg.telegramPolling) {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Telegram is not configured on this instance"})
	}
	code, err := randomCode(18)
	if err != nil {
		return serverError(c, err)
	}
	expires := time.Now().Add(ChannelLinkTTL).UTC()
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(c.Context(), `DELETE FROM channel_link_codes WHERE org_id = $1 AND channel_id = $2`, org, ch.ID); err != nil {
			return err
		}
		_, err := tx.Exec(c.Context(),
			`INSERT INTO channel_link_codes (code_hash, org_id, channel_id, expires_at) VALUES ($1, $2, $3, $4)`,
			hashCode(code), org, ch.ID, expires)
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.channel.link_started", ch.Name, map[string]any{"id": ch.ID})
	return c.JSON(fiber.Map{"code": code, "command": "/link@" + rt.bot() + " " + code, "bot_username": rt.bot(),
		"expires_at": expires})
}

// resendConfirmations mails a new link to every unconfirmed address of an
// email channel, within the daily cap.
func (rt *alertsRuntime) resendConfirmations(c *fiber.Ctx) error {
	org := orgID(c)
	ch, err := rt.loadChannel(c, org, false)
	if err != nil {
		return channelError(c, err)
	}
	if ch.Kind != channels.KindEmail {
		return badRequest(c, "only email channels have addresses to confirm")
	}
	if !rt.cfg.smtp.Enabled() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "SMTP is not configured on this instance"})
	}
	var mails []pendingMail
	var name string
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		addrs, err := loadAddresses(c.Context(), tx, org, []uuid.UUID{ch.ID})
		if err != nil {
			return err
		}
		var pending []string
		for _, a := range addrs[ch.ID] {
			if !a.Confirmed {
				pending = append(pending, a.Address)
			}
		}
		name = orgName(c.Context(), tx, org)
		mails, err = rt.issueConfirmations(c.Context(), tx, org, ch.ID, pending)
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	rt.sendConfirmations(name, mails)
	logActivity(c, rt.db, &org, "alerts.channel.confirmations_sent", ch.Name, map[string]any{"id": ch.ID, "sent": len(mails)})
	return rt.channelJSON(c, org, ch, 200)
}

// confirmEmail is the link of a confirmation mail (no login: the token is
// the credential, single use, 7 days).
func (rt *alertsRuntime) confirmEmail(c *fiber.Ctx) error {
	token := c.Query("token")
	c.Set("Content-Type", "text/plain; charset=utf-8")
	c.Set("Referrer-Policy", "no-referrer")
	if token == "" || len(token) > 64 {
		return c.Status(400).SendString("This confirmation link is not valid.")
	}
	var addr *string
	if err := rt.db.QueryRow(c.Context(), `SELECT confirm_channel_email($1)`, hashCode(token)).Scan(&addr); err != nil {
		return c.Status(500).SendString("The confirmation failed; try again later.")
	}
	if addr == nil {
		return c.Status(404).SendString("This confirmation link is invalid, expired or already used.")
	}
	return c.SendString("Confirmed: " + *addr + " will receive Guard Spec alert notifications of this organization.")
}
