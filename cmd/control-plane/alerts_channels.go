// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/giaplee/guard-spec/internal/alerts"
	"github.com/giaplee/guard-spec/internal/alerts/channels"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// channelView is a channel as the API shows it: secret_set, never the value.
type channelView struct {
	alerts.ChannelRow
	SecretSet bool `json:"secret_set"`
}

func (rt *alertsRuntime) view(c alerts.ChannelRow) channelView {
	set := false
	if c.SecretEnv != nil && alerts.AllowedSecretEnv(*c.SecretEnv) {
		set = rt.cfg.getenv(*c.SecretEnv) != ""
	}
	return channelView{ChannelRow: c, SecretSet: set}
}

var (
	chatIDRe    = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)
	slackChanRe = regexp.MustCompile(`^[#@]?[A-Za-z0-9._-]{1,80}$`)
)

// channelKeys are the config keys each kind accepts.
var channelKeys = map[string][]string{
	channels.KindTelegram: {"chat_id"},
	channels.KindSlack:    {"mode", "channel"},
	channels.KindTeams:    {},
	channels.KindWebhook:  {"url", "allow_private"},
	channels.KindA2A:      {"agent_card_url", "allow_private"},
	channels.KindEmail:    {"to", "lang"},
}

// validateChannel checks a channel's kind, config and secret_env.
func (rt *alertsRuntime) validateChannel(c *alerts.ChannelRow) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || utf8.RuneCountInString(c.Name) > 100 {
		return errors.New("name is required (at most 100 characters)")
	}
	keys, ok := channelKeys[c.Kind]
	if !ok {
		return fmt.Errorf("kind must be one of %s", strings.Join(channels.Kinds, ", "))
	}
	if c.Config == nil {
		c.Config = map[string]any{}
	}
	for k := range c.Config {
		if !slices.Contains(keys, k) {
			return fmt.Errorf("config.%s is not a setting of %s channels", k, c.Kind)
		}
	}
	if raw, _ := json.Marshal(c.Config); len(raw) > 4096 {
		return errors.New("config is too large")
	}
	str := func(k string) (string, error) {
		v, ok := c.Config[k]
		if !ok {
			return "", nil
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("config.%s must be a string", k)
		}
		return s, nil
	}
	if v, ok := c.Config["allow_private"]; ok {
		if _, isBool := v.(bool); !isBool {
			return errors.New("config.allow_private must be true or false")
		}
	}
	if c.SecretEnv != nil && *c.SecretEnv == "" {
		c.SecretEnv = nil
	}
	if c.SecretEnv != nil && !alerts.AllowedSecretEnv(*c.SecretEnv) {
		return errors.New("secret_env must be an environment variable name (A-Z, 0-9, _) starting with " +
			strings.Join(alerts.SecretEnvPrefixes, ", "))
	}
	needSecret := func(what string) error {
		if c.SecretEnv == nil {
			return fmt.Errorf("secret_env is required: the variable that holds the %s", what)
		}
		return nil
	}
	private, _ := c.Config["allow_private"].(bool)
	switch c.Kind {
	case channels.KindTelegram:
		chat, err := str("chat_id")
		if err != nil {
			return err
		}
		if !chatIDRe.MatchString(chat) {
			return errors.New("config.chat_id must be a Telegram chat id such as -1001234567890")
		}
		if c.SecretEnv == nil && rt.cfg.telegramToken == "" {
			return errors.New("secret_env is required (TELEGRAM_BOT_TOKEN_*) unless the instance sets TELEGRAM_BOT_TOKEN")
		}
	case channels.KindSlack:
		mode, err := str("mode")
		if err != nil {
			return err
		}
		switch mode {
		case "", "bot":
			c.Config["mode"] = "bot"
			ch, err := str("channel")
			if err != nil {
				return err
			}
			if !slackChanRe.MatchString(ch) {
				return errors.New("config.channel must be a Slack channel id or name")
			}
			return needSecret("bot token")
		case "webhook":
			if _, ok := c.Config["channel"]; ok {
				return errors.New("config.channel is set by the incoming webhook itself")
			}
			return needSecret("incoming webhook URL")
		default:
			return errors.New("config.mode must be bot or webhook")
		}
	case channels.KindTeams:
		return needSecret("Workflows webhook URL")
	case channels.KindWebhook:
		u, err := str("url")
		if err != nil {
			return err
		}
		if err := rt.guard.CheckURL(u, private); err != nil {
			return fmt.Errorf("config.url: %v", err)
		}
		return needSecret("HMAC signing secret")
	case channels.KindA2A:
		u, err := str("agent_card_url")
		if err != nil {
			return err
		}
		if err := rt.guard.CheckURL(u, private); err != nil {
			return fmt.Errorf("config.agent_card_url: %v", err)
		}
	case channels.KindEmail:
		if c.SecretEnv != nil {
			return errors.New("email channels use SMTP_URL; secret_env is not used")
		}
		list, ok := c.Config["to"].([]any)
		if !ok || len(list) == 0 || len(list) > 20 {
			return errors.New("config.to must list 1 to 20 email addresses")
		}
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return errors.New("config.to must list email addresses")
			}
			if a, err := mail.ParseAddress(s); err != nil || a.Address != s {
				return fmt.Errorf("config.to: %q is not an email address", s)
			}
		}
		lang, err := str("lang")
		if err != nil {
			return err
		}
		if lang != "" && lang != "en" && lang != "vi" {
			return errors.New("config.lang must be en or vi")
		}
	}
	return nil
}

func channelError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return notFound(c)
	case isUniqueViolation(err):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": errDuplicateName.Error()})
	case isPageError(err):
		return badPage(c, err)
	}
	return serverError(c, err)
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
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (alerts.ChannelRow, error) { return alerts.ScanChannel(r) })
		return err
	})
	if err != nil {
		return channelError(c, err)
	}
	list, next := page(list, pg.Limit, func(r alerts.ChannelRow) pageCursor { return timeCursor(r.CreatedAt, r.ID.String()) })
	items := make([]channelView, 0, len(list))
	for _, ch := range list {
		items = append(items, rt.view(ch))
	}
	return envelope(c, items, next, total, false)
}

func (rt *alertsRuntime) loadChannel(c *fiber.Ctx, org uuid.UUID, lock bool) (alerts.ChannelRow, error) {
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

func (rt *alertsRuntime) getChannel(c *fiber.Ctx) error {
	ch, err := rt.loadChannel(c, orgID(c), false)
	if err != nil {
		return channelError(c, err)
	}
	return c.JSON(rt.view(ch))
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
	if err := rt.validateChannel(&ch); err != nil {
		return badRequest(c, err.Error())
	}
	cfg, _ := json.Marshal(ch.Config)
	err := tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(c.Context(),
			`INSERT INTO notification_channels (id, org_id, name, kind, config, secret_env, enabled)
			 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING created_at, updated_at`,
			ch.ID, org, ch.Name, ch.Kind, cfg, ch.SecretEnv, ch.Enabled).Scan(&ch.CreatedAt, &ch.UpdatedAt)
	})
	if err != nil {
		return channelError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.channel.created", ch.Name, map[string]any{"id": ch.ID, "kind": ch.Kind})
	return c.Status(201).JSON(rt.view(ch))
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
	err = tenant.WithOrg(c.Context(), rt.db, org, func(tx pgx.Tx) error {
		if ch, err = alerts.ScanChannel(tx.QueryRow(c.Context(),
			`SELECT `+alerts.ChannelColumns+` FROM notification_channels WHERE org_id = $1 AND id = $2 FOR UPDATE`, org, id)); err != nil {
			return err
		}
		if in.Kind != nil && *in.Kind != ch.Kind {
			invalid = errors.New("kind cannot be changed; create a new channel")
			return nil
		}
		if invalid = in.apply(&ch); invalid != nil {
			return nil
		}
		if invalid = rt.validateChannel(&ch); invalid != nil {
			return nil
		}
		cfg, _ := json.Marshal(ch.Config)
		return tx.QueryRow(c.Context(),
			`UPDATE notification_channels SET name = $3, config = $4, secret_env = $5, enabled = $6, updated_at = NOW()
			 WHERE org_id = $1 AND id = $2 RETURNING updated_at`,
			org, id, ch.Name, cfg, ch.SecretEnv, ch.Enabled).Scan(&ch.UpdatedAt)
	})
	if invalid != nil {
		return badRequest(c, invalid.Error())
	}
	if err != nil {
		return channelError(c, err)
	}
	logActivity(c, rt.db, &org, "alerts.channel.updated", ch.Name, map[string]any{"id": ch.ID, "enabled": ch.Enabled})
	return c.JSON(rt.view(ch))
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

// testChannel sends a test notification synchronously.
func (rt *alertsRuntime) testChannel(c *fiber.Ctx) error {
	org := orgID(c)
	ch, err := rt.loadChannel(c, org, false)
	if err != nil {
		return channelError(c, err)
	}
	now := time.Now().UTC()
	base := strings.TrimRight(rt.publicURL, "/")
	p := channels.Payload{
		Schema: channels.SchemaV1, EventID: "test_" + uuid.NewString(), AlertID: "test",
		Rule: channels.RuleRef{ID: "test", Name: "Test notification: " + ch.Name}, State: "firing", Severity: "info",
		OrgID: org.String(), Count: 1, WindowSeconds: 300, FirstAt: now, LastAt: now, Group: map[string]string{},
		Samples: []channels.Sample{}, Test: true,
		Links: channels.Links{Alert: base + "/ui/alerts/history", Requests: base + "/ui/requests"},
	}
	start := time.Now()
	res, err := rt.disp.TestChannel(c.Context(), &ch, p)
	latency := time.Since(start).Milliseconds()
	out := fiber.Map{"ok": err == nil, "status": res.Status, "latency_ms": latency}
	if err != nil {
		ce := channels.AsError(err)
		out["status"] = ce.Status
		out["error"] = channels.Redact(ce.Msg)
	}
	logActivity(c, rt.db, &org, "alerts.channel.tested", ch.Name, map[string]any{"id": ch.ID, "ok": err == nil})
	return c.JSON(out)
}
