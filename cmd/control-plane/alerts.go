// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/alerts"
	"github.com/guard-spec/guard-spec/internal/alerts/channels"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/proxy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real-time alerts and notifications (docs/alerts.md): the API of rules,
// channels, groups, alert history, deliveries, personal preferences and
// links, in-app notifications and their SSE stream, and the Telegram
// webhook. The worker that evaluates rules and delivers runs in main.

// alertsConfig is the instance configuration of alerts, from the
// environment. Secrets stay here and in channel secret_env variables; none
// is stored in the database.
type alertsConfig struct {
	getenv          func(string) string
	privateOrgs     alerts.PrivateOrgs // ALERTS_PRIVATE_ORGS
	emailDailyCap   int                // ALERTS_EMAIL_DAILY_CAP
	telegramToken   string             // TELEGRAM_BOT_TOKEN: personal chats and the /start link
	telegramBot     string             // TELEGRAM_BOT_USERNAME, for deep links
	telegramSecret  string             // TELEGRAM_WEBHOOK_SECRET
	telegramPolling bool               // TELEGRAM_POLLING=1
	slackToken      string             // SLACK_BOT_TOKEN: personal DMs and lookupByEmail
	smtp            channels.SMTPConfig
	secretOrgs      alerts.SecretOrgs // ALERTS_SECRET_ORGS
	lang            string            // ALERTS_LANG: en (default) or vi
	// API origins; tests point them at fakes.
	telegramAPI, slackAPI string
}

func loadAlertsConfig(getenv func(string) string) (alertsConfig, error) {
	secretOrgs, err := alerts.ParseSecretOrgs(getenv("ALERTS_SECRET_ORGS"))
	privateOrgs, perr := alerts.ParsePrivateOrgs(getenv("ALERTS_PRIVATE_ORGS"))
	if err == nil {
		err = perr
	}
	if err == nil && getenv("ALERTS_ALLOW_PRIVATE_URLS") != "" {
		err = errors.New("ALERTS_ALLOW_PRIVATE_URLS was replaced by ALERTS_PRIVATE_ORGS, a list of the org ids " +
			"whose channels may reach private addresses")
	}
	emailCap := alerts.DefaultEmailDailyCap
	if v := getenv("ALERTS_EMAIL_DAILY_CAP"); v != "" {
		n, cerr := strconv.Atoi(v)
		if cerr != nil || n < 1 {
			if err == nil {
				err = errors.New("ALERTS_EMAIL_DAILY_CAP must be a positive number")
			}
		} else {
			emailCap = n
		}
	}
	lang := getenv("ALERTS_LANG")
	if lang != "vi" {
		lang = "en"
	}
	return alertsConfig{
		secretOrgs:      secretOrgs,
		getenv:          getenv,
		privateOrgs:     privateOrgs,
		emailDailyCap:   emailCap,
		telegramToken:   getenv(alerts.EnvTelegramToken),
		telegramBot:     strings.TrimPrefix(getenv("TELEGRAM_BOT_USERNAME"), "@"),
		telegramSecret:  getenv("TELEGRAM_WEBHOOK_SECRET"),
		telegramPolling: getenv("TELEGRAM_POLLING") == "1",
		slackToken:      getenv(alerts.EnvSlackToken),
		smtp:            channels.SMTPConfig{URL: getenv("SMTP_URL"), From: getenv("SMTP_FROM")},
		lang:            lang,
		// Test-only: point Telegram and Slack at fakes (end-to-end runs).
		telegramAPI: originOr(getenv("ALERTS_TEST_TELEGRAM_API"), channels.TelegramAPI),
		slackAPI:    originOr(getenv("ALERTS_TEST_SLACK_API"), channels.SlackAPI),
	}, err
}

func originOr(v, def string) string {
	if v = strings.TrimRight(v, "/"); v != "" {
		return v
	}
	return def
}

// alertsRuntime holds what the alert handlers and the worker share.
type alertsRuntime struct {
	db        *pgxpool.Pool
	cfg       alertsConfig
	publicURL string
	engine    *alerts.Engine
	disp      *alerts.Dispatcher
	hub       *alerts.Hub
	emitter   *events.Emitter
	tg        *channels.Telegram
	slack     *channels.Slack
	guard     channels.Guard
	sessions  auth.SessionLookup
	// base ends open SSE streams at shutdown.
	base    context.Context
	botName atomic.Pointer[string]
}

func newAlertsRuntime(db *pgxpool.Pool, s *appSettings, sessions auth.SessionLookup) *alertsRuntime {
	cfg := s.alertsCfg
	if cfg == nil {
		getenv := s.getenv
		if getenv == nil {
			getenv = os.Getenv
		}
		c, err := loadAlertsConfig(getenv)
		if err != nil {
			slog.Error("alerts config", "err", err)
		}
		cfg = &c
	}
	api := proxy.SafeClient(false, channels.Timeout) // fixed operator origins
	guard := channels.NewGuard(cfg.privateOrgs)
	tg := &channels.Telegram{Base: cfg.telegramAPI, Client: api}
	slack := &channels.Slack{Base: cfg.slackAPI, Client: api, Guard: guard}
	caps := alerts.Caps{Telegram: cfg.telegramToken != "", Slack: cfg.slackToken != "", SMTP: cfg.smtp.Enabled()}
	base := s.alertsBase
	if base == nil {
		base = context.Background()
	}
	rt := &alertsRuntime{
		db: db, cfg: *cfg, publicURL: s.publicURL, hub: alerts.NewHub(), tg: tg, slack: slack, guard: guard,
		sessions: sessions, base: base,
		engine: &alerts.Engine{DB: db, PublicURL: s.publicURL, Caps: caps, Lang: cfg.lang},
		disp: &alerts.Dispatcher{DB: db, Getenv: cfg.getenv, Lang: cfg.lang, TelegramToken: cfg.telegramToken, SlackToken: cfg.slackToken, SecretOrgs: cfg.secretOrgs, EmailDailyCap: cfg.emailDailyCap, Senders: map[string]channels.Sender{
			channels.KindTelegram: tg,
			channels.KindSlack:    slack,
			channels.KindTeams:    &channels.Teams{Guard: guard},
			channels.KindWebhook:  &channels.Webhook{Guard: guard},
			channels.KindA2A:      &channels.A2A{Guard: guard},
			channels.KindEmail:    &channels.Email{SMTP: cfg.smtp},
		}},
	}
	if !s.noAlertEvents {
		rt.emitter = events.New(db, events.Config{Source: "control_plane"})
		activityEmitter.Store(rt.emitter)
	}
	return rt
}

// worker returns the alert worker of this runtime.
func (rt *alertsRuntime) worker() *alerts.Worker {
	return &alerts.Worker{DB: rt.db, Engine: rt.engine, Dispatcher: rt.disp}
}

// run starts the worker, the SSE hub and the Telegram polling fallback
// until ctx ends.
func (rt *alertsRuntime) run(ctx context.Context) {
	go rt.hub.Run(ctx, rt.db)
	if rt.cfg.telegramPolling && rt.cfg.telegramToken != "" {
		go rt.pollTelegram(ctx)
	}
	if rt.cfg.telegramToken != "" && rt.cfg.telegramBot == "" {
		go func() {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if name, err := rt.tg.GetMe(cctx, rt.cfg.telegramToken); err == nil {
				rt.setBotName(name)
			} else {
				slog.Warn("telegram getMe failed; set TELEGRAM_BOT_USERNAME", "err", channels.Redact(err.Error(), rt.cfg.telegramToken))
			}
		}()
	}
	rt.worker().Run(ctx)
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rt.emitter.Close(closeCtx)
}

func (rt *alertsRuntime) setBotName(name string) { rt.botName.Store(&name) }

// bot is the Telegram bot username: TELEGRAM_BOT_USERNAME or getMe.
func (rt *alertsRuntime) bot() string {
	if rt.cfg.telegramBot != "" {
		return rt.cfg.telegramBot
	}
	if p := rt.botName.Load(); p != nil {
		return *p
	}
	return ""
}

// registerAlertRoutes mounts the alert API.
func registerAlertRoutes(v1, authed fiber.Router, db *pgxpool.Pool, rt *alertsRuntime, perIP func(int) fiber.Handler) {
	// Reads are open to viewers (alerts.read); channels never show secrets.
	viewer := auth.RequireRole(db, auth.RoleViewer)
	admin := auth.RequireRole(db, auth.RoleAdmin)
	perUser := limiter.New(limiter.Config{Max: 10, Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string { return "alerts:" + auth.UserID(c).String() }})

	authed.Get("/alerts/capabilities", rt.capabilities)
	authed.Get("/me/channel-links", rt.listLinks)
	authed.Delete("/me/channel-links/:kind", rt.deleteLink)
	authed.Put("/me/channel-links/email", perUser, rt.emailLink)
	authed.Post("/me/channel-links/email/confirm", perUser, rt.emailLinkConfirm)
	authed.Post("/me/channel-links/telegram/start", perUser, rt.telegramStart)
	authed.Post("/me/channel-links/slack", perUser, rt.slackLink)
	authed.Get("/notifications", rt.listNotifications)
	authed.Post("/notifications/read", rt.readNotifications)
	authed.Get("/notifications/stream", rt.stream)

	org := "/organizations/:orgId"
	authed.Get(org+"/alert-rules", viewer, rt.listRules)
	authed.Post(org+"/alert-rules", admin, rt.createRule)
	authed.Get(org+"/alert-rules/:id", viewer, rt.getRule)
	authed.Patch(org+"/alert-rules/:id", admin, rt.updateRule)
	authed.Delete(org+"/alert-rules/:id", admin, rt.deleteRule)
	authed.Post(org+"/alert-rules/:id/test", admin, perUser, rt.testRule)

	authed.Get(org+"/notification-channels", viewer, rt.listChannels)
	authed.Post(org+"/notification-channels", admin, rt.createChannel)
	authed.Get(org+"/notification-channels/:id", viewer, rt.getChannel)
	authed.Patch(org+"/notification-channels/:id", admin, rt.updateChannel)
	authed.Delete(org+"/notification-channels/:id", admin, rt.deleteChannel)
	authed.Post(org+"/notification-channels/:id/test", admin, perUser, rt.testChannel)
	authed.Post(org+"/notification-channels/:id/telegram-link", admin, perUser, rt.telegramChannelLink)
	authed.Post(org+"/notification-channels/:id/email-confirmations", admin, perUser, rt.resendConfirmations)

	authed.Get(org+"/user-groups", viewer, rt.listGroups)
	authed.Post(org+"/user-groups", admin, rt.createGroup)
	authed.Get(org+"/user-groups/:id", viewer, rt.getGroup)
	authed.Patch(org+"/user-groups/:id", admin, rt.updateGroup)
	authed.Delete(org+"/user-groups/:id", admin, rt.deleteGroup)
	authed.Put(org+"/user-groups/:id/members", admin, rt.putGroupMembers)

	authed.Get(org+"/alerts", viewer, rt.listAlerts)
	authed.Get(org+"/alerts/:id", viewer, rt.getAlert)
	authed.Get(org+"/notification-deliveries", admin, rt.listDeliveries)

	authed.Get(org+"/me/notification-prefs", viewer, rt.getPrefs)
	authed.Put(org+"/me/notification-prefs", viewer, rt.putPrefs)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// withUser runs fn in a transaction scoped to user (app.user_id): the
// user's own links, link codes and notifications across orgs.
func withUser(ctx context.Context, db *pgxpool.Pool, user uuid.UUID, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, user.String()); err != nil {
			return err
		}
		return fn(tx)
	})
}

// strictJSON decodes body into v, refusing unknown fields.
func strictJSON(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid body: " + err.Error())
	}
	return nil
}

func badRequest(c *fiber.Ctx, msg string) error {
	return c.Status(400).JSON(fiber.Map{"error": msg})
}

func notFound(c *fiber.Ctx) error { return c.Status(404).JSON(fiber.Map{"error": "not found"}) }

func idParam(c *fiber.Ctx) (uuid.UUID, error) { return uuid.Parse(c.Params("id")) }

// envelope writes the list envelope of the contract.
func envelope[T any](c *fiber.Ctx, items []T, next *string, total int64, capped bool) error {
	return c.JSON(fiber.Map{"items": items, "next_cursor": next, "total": total, "total_capped": capped})
}

// capabilities answers GET /v1/alerts/capabilities[?org_id=]. allow_private_urls
// is per org (ALERTS_PRIVATE_ORGS): true only with an org_id the caller
// belongs to and the operator listed.
func (rt *alertsRuntime) capabilities(c *fiber.Ctx) error {
	private := false
	if raw := c.Query("org_id"); raw != "" {
		org, err := uuid.Parse(raw)
		if err != nil {
			return badRequest(c, "invalid org_id")
		}
		if rt.guard.AllowsPrivate(org.String()) {
			var member bool
			if err := rt.db.QueryRow(c.Context(), `SELECT EXISTS (SELECT 1 FROM user_organizations($1) WHERE id = $2)`,
				authUser(c), org).Scan(&member); err != nil {
				return serverError(c, err)
			}
			private = member
		}
	}
	tgEnabled := rt.cfg.telegramToken != "" && rt.bot() != "" &&
		(rt.cfg.telegramSecret != "" || rt.cfg.telegramPolling)
	return c.JSON(fiber.Map{
		"telegram":           fiber.Map{"enabled": tgEnabled, "bot_username": rt.bot()},
		"slack_bot":          rt.cfg.slackToken != "",
		"smtp":               rt.cfg.smtp.Enabled(),
		"a2a":                true,
		"webhook":            true,
		"teams":              true,
		"allow_private_urls": private,
		"email_confirmation": rt.cfg.smtp.Enabled(),
		"email_daily_cap":    rt.cfg.emailDailyCap,
	})
}
