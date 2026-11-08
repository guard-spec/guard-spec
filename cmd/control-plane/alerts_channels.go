// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/alerts"
	"github.com/guard-spec/guard-spec/internal/alerts/channels"
	"github.com/jackc/pgx/v5"
)

// channelView is a channel as the API shows it: secret_set, never the value.
// verified: a Telegram channel on the instance bot whose chat sent /link, an
// email channel with a confirmed address; every other channel is verified.
// addresses: the email addresses and whether each confirmed.
type channelView struct {
	alerts.ChannelRow
	SecretSet bool           `json:"secret_set"`
	Verified  bool           `json:"verified"`
	Addresses []emailAddress `json:"addresses,omitempty"`
}

type emailAddress struct {
	Address     string     `json:"address"`
	Confirmed   bool       `json:"confirmed"`
	ConfirmedAt *time.Time `json:"confirmed_at"`
	SentAt      *time.Time `json:"sent_at"`
}

func (rt *alertsRuntime) view(org uuid.UUID, c alerts.ChannelRow, addrs []emailAddress) channelView {
	set := false
	if c.SecretEnv != nil && alerts.CheckSecretEnv(c.Kind, *c.SecretEnv, org, rt.cfg.secretOrgs) == nil {
		set = rt.cfg.getenv(*c.SecretEnv) != ""
	}
	v := channelView{ChannelRow: c, SecretSet: set, Verified: true}
	switch c.Kind {
	case channels.KindTelegram:
		v.Verified = c.SecretEnv != nil || c.VerifiedAt != nil
	case channels.KindEmail:
		v.Addresses, v.Verified = addrs, false
		if v.Addresses == nil {
			v.Addresses = []emailAddress{}
		}
		for _, a := range addrs {
			v.Verified = v.Verified || a.Confirmed
		}
	}
	return v
}

var (
	chatIDRe    = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)
	slackChanRe = regexp.MustCompile(`^[#@]?[A-Za-z0-9._-]{1,80}$`)
)

// secretInQuery reports a URL query parameter that looks like a credential.
func secretInQuery(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for k := range u.Query() {
		k = strings.ToLower(k)
		for _, w := range []string{"token", "key", "secret", "sig", "pass", "auth", "code"} {
			if strings.Contains(k, w) {
				return true
			}
		}
	}
	return false
}

// configChat is the chat_id of a Telegram channel.
func configChat(c *alerts.ChannelRow) string {
	s, _ := c.Config["chat_id"].(string)
	return s
}

// channelKeys are the config keys each kind accepts.
var channelKeys = map[string][]string{
	channels.KindTelegram:  {"chat_id"},
	channels.KindSlack:     {"mode", "channel"},
	channels.KindTeams:     {},
	channels.KindPagerDuty: {"region"},
	channels.KindOpsgenie:  {"region"},
	channels.KindWebhook:   {"url", "allow_private"},
	channels.KindA2A:       {"agent_card_url", "allow_private"},
	channels.KindEmail:     {"to", "lang"},
}

// validateChannel checks a channel's kind, config and secret_env.
func (rt *alertsRuntime) validateChannel(org uuid.UUID, c *alerts.ChannelRow, prev *alerts.ChannelRow) error {
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
	if c.SecretEnv != nil && c.Kind != channels.KindEmail {
		if err := alerts.CheckSecretEnv(c.Kind, *c.SecretEnv, org, rt.cfg.secretOrgs); err != nil {
			return err
		}
	}
	needSecret := func(what string) error {
		if c.SecretEnv == nil {
			return fmt.Errorf("secret_env is required: the variable that holds the %s", what)
		}
		return nil
	}
	private, _ := c.Config["allow_private"].(bool)
	if private && !rt.guard.AllowsPrivate(org.String()) {
		return errors.New("config.allow_private is not allowed for this organization; the operator lists it in ALERTS_PRIVATE_ORGS")
	}
	switch c.Kind {
	case channels.KindTelegram:
		chat, err := str("chat_id")
		if err != nil {
			return err
		}
		if c.SecretEnv != nil {
			// The org's own bot: it can only post where it was added.
			if !chatIDRe.MatchString(chat) {
				return errors.New("config.chat_id must be a Telegram chat id such as -1001234567890")
			}
			break
		}
		if rt.cfg.telegramToken == "" {
			return errors.New("secret_env is required (TELEGRAM_BOT_TOKEN_*) unless the instance sets TELEGRAM_BOT_TOKEN")
		}
		// The instance bot posts only to a chat that sent /link <code>, which
		// sets chat_id; a client cannot choose it.
		if chat != "" && (prev == nil || prev.SecretEnv != nil || configChat(prev) != chat) {
			return errors.New("config.chat_id of a channel on the instance bot is set by sending the /link code in the chat")
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
	case channels.KindPagerDuty, channels.KindOpsgenie:
		if r, ok := c.Config["region"]; ok && r != "us" && r != "eu" {
			return errors.New("config.region must be us or eu")
		}
		if c.Kind == channels.KindPagerDuty {
			return needSecret("Events API v2 routing key")
		}
		return needSecret("API integration key")
	case channels.KindWebhook:
		u, err := str("url")
		if err != nil {
			return err
		}
		if err := rt.guard.CheckURL(u, private, org.String()); err != nil {
			return fmt.Errorf("config.url: %v", err)
		}
		if secretInQuery(u) {
			return errors.New("config.url must not carry a token in its query: config is visible to members; " +
				"receivers authenticate deliveries with the signature")
		}
		return needSecret("HMAC signing secret")
	case channels.KindA2A:
		u, err := str("agent_card_url")
		if err != nil {
			return err
		}
		if err := rt.guard.CheckURL(u, private, org.String()); err != nil {
			return fmt.Errorf("config.agent_card_url: %v", err)
		}
		if secretInQuery(u) {
			return errors.New("config.agent_card_url must not carry a token in its query; put it in secret_env")
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
	res, err := rt.disp.TestChannel(c.Context(), org, &ch, p)
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
