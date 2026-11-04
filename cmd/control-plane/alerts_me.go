// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/giaplee/guard-spec/internal/alerts/channels"
	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/proxy"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func authUser(c *fiber.Ctx) uuid.UUID { return auth.UserID(c) }

// TelegramCodeTTL is how long a /start code works.
const TelegramCodeTTL = 10 * time.Minute

// ── Personal links ──────────────────────────────────────────────────────────

type linkView struct {
	Kind       string     `json:"kind"`
	Address    string     `json:"address"`
	VerifiedAt *time.Time `json:"verified_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (rt *alertsRuntime) listLinks(c *fiber.Ctx) error {
	user := authUser(c)
	var list []linkView
	err := withUser(c.Context(), rt.db, user, func(tx pgx.Tx) error {
		rows, err := tx.Query(c.Context(),
			`SELECT kind, address, verified_at, created_at FROM user_channel_links WHERE user_id = $1 ORDER BY kind`, user)
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (linkView, error) {
			var l linkView
			return l, r.Scan(&l.Kind, &l.Address, &l.VerifiedAt, &l.CreatedAt)
		})
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	if list == nil {
		list = []linkView{}
	}
	return envelope(c, list, nil, int64(len(list)), false)
}

func (rt *alertsRuntime) deleteLink(c *fiber.Ctx) error {
	user, kind := authUser(c), c.Params("kind")
	if !strings.Contains("|telegram|slack|email|", "|"+kind+"|") {
		return notFound(c)
	}
	var n int64
	err := withUser(c.Context(), rt.db, user, func(tx pgx.Tx) error {
		tag, err := tx.Exec(c.Context(), `DELETE FROM user_channel_links WHERE user_id = $1 AND kind = $2`, user, kind)
		n = tag.RowsAffected()
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	if n == 0 {
		return notFound(c)
	}
	logUserEvent(c.Context(), rt.db, user, "alerts.link.deleted", clientIP(c), map[string]any{"kind": kind})
	return c.SendStatus(204)
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// telegramStart issues a one-time /start code (stored hashed) and the deep
// link that sends it to the bot.
func (rt *alertsRuntime) telegramStart(c *fiber.Ctx) error {
	if rt.cfg.telegramToken == "" || rt.bot() == "" || (rt.cfg.telegramSecret == "" && !rt.cfg.telegramPolling) {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Telegram is not configured on this instance"})
	}
	user := authUser(c)
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return serverError(c, err)
	}
	code := base64.RawURLEncoding.EncodeToString(buf) // 24 characters of A-Za-z0-9_-
	expires := time.Now().Add(TelegramCodeTTL).UTC()
	err := withUser(c.Context(), rt.db, user, func(tx pgx.Tx) error {
		// One open code per user: a new one replaces the old.
		if _, err := tx.Exec(c.Context(), `DELETE FROM telegram_link_codes WHERE user_id = $1`, user); err != nil {
			return err
		}
		_, err := tx.Exec(c.Context(), `INSERT INTO telegram_link_codes (code_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
			hashCode(code), user, expires)
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	return c.JSON(fiber.Map{"code": code, "deep_link": "https://t.me/" + rt.bot() + "?start=" + code, "expires_at": expires})
}

// handleTelegramUpdate links a chat from a private "/start <code>" message
// and answers the chat.
func (rt *alertsRuntime) handleTelegramUpdate(ctx context.Context, u *channels.TelegramUpdate) {
	chat, code := u.StartCode()
	if code == "" {
		return
	}
	var user *uuid.UUID
	err := rt.db.QueryRow(ctx, `SELECT redeem_telegram_link_code($1, $2)`, hashCode(code), chat).Scan(&user)
	reply := "This link code is invalid or expired. Create a new one under My account > Notifications."
	if err != nil {
		slog.Warn("telegram link failed", "err", err)
		return
	}
	if user != nil {
		reply = "Linked. Guard Spec alerts for your account will arrive in this chat."
		logUserEvent(ctx, rt.db, *user, "alerts.link.created", "", map[string]any{"kind": "telegram"})
	}
	cctx, cancel := context.WithTimeout(ctx, channels.Timeout)
	defer cancel()
	_, _ = rt.tg.Call(cctx, rt.cfg.telegramToken, "sendMessage", map[string]any{"chat_id": chat, "text": reply}, nil)
}

// telegramWebhook receives bot updates; Telegram sends the secret configured
// with setWebhook in X-Telegram-Bot-Api-Secret-Token.
func (rt *alertsRuntime) telegramWebhook(c *fiber.Ctx) error {
	secret := rt.cfg.telegramSecret
	if secret == "" || rt.cfg.telegramToken == "" {
		return notFound(c)
	}
	got := c.Get("X-Telegram-Bot-Api-Secret-Token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid secret"})
	}
	if len(c.Body()) > 64<<10 {
		return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "too large"})
	}
	var u channels.TelegramUpdate
	if err := json.Unmarshal(c.Body(), &u); err != nil {
		return c.JSON(fiber.Map{}) // nothing Telegram should retry
	}
	rt.handleTelegramUpdate(c.Context(), &u)
	return c.JSON(fiber.Map{})
}

// pollTelegram is the long-polling fallback (TELEGRAM_POLLING=1).
func (rt *alertsRuntime) pollTelegram(ctx context.Context) {
	poller := &channels.Telegram{Base: rt.tg.Base, Client: proxy.SafeClient(false, 35*time.Second)}
	var offset int64
	for ctx.Err() == nil {
		updates, err := poller.GetUpdates(ctx, rt.cfg.telegramToken, offset, 25*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("telegram getUpdates failed", "err", channels.Redact(err.Error(), rt.cfg.telegramToken))
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		for i := range updates {
			if updates[i].UpdateID >= offset {
				offset = updates[i].UpdateID + 1
			}
			rt.handleTelegramUpdate(ctx, &updates[i])
		}
	}
}

// slackLink links the caller's Slack account by their email address.
func (rt *alertsRuntime) slackLink(c *fiber.Ctx) error {
	if rt.cfg.slackToken == "" {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Slack is not configured on this instance"})
	}
	user := authUser(c)
	var email string
	if err := rt.db.QueryRow(c.Context(), `SELECT email FROM users WHERE id = $1`, user).Scan(&email); err != nil {
		return serverError(c, err)
	}
	id, err := rt.slack.LookupByEmail(c.Context(), rt.cfg.slackToken, email)
	if err != nil {
		var ce *channels.Error
		if errors.As(err, &ce) && ce.Permanent {
			return c.Status(404).JSON(fiber.Map{"error": "no Slack user has your email address"})
		}
		slog.Warn("slack lookup failed", "err", channels.Redact(err.Error(), rt.cfg.slackToken))
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "Slack could not be reached"})
	}
	var l linkView
	err = withUser(c.Context(), rt.db, user, func(tx pgx.Tx) error {
		return tx.QueryRow(c.Context(),
			`INSERT INTO user_channel_links (user_id, kind, address, verified_at) VALUES ($1, 'slack', $2, NOW())
			 ON CONFLICT (user_id, kind) DO UPDATE SET address = EXCLUDED.address, verified_at = NOW()
			 RETURNING kind, address, verified_at, created_at`, user, id).Scan(&l.Kind, &l.Address, &l.VerifiedAt, &l.CreatedAt)
	})
	if err != nil {
		return serverError(c, err)
	}
	logUserEvent(c.Context(), rt.db, user, "alerts.link.created", clientIP(c), map[string]any{"kind": "slack"})
	return c.JSON(l)
}

// ── In-app notifications ────────────────────────────────────────────────────

type notificationView struct {
	ID        uuid.UUID  `json:"id"`
	OrgID     uuid.UUID  `json:"org_id"`
	AlertID   *uuid.UUID `json:"alert_id"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	Severity  string     `json:"severity"`
	ReadAt    *time.Time `json:"read_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// Notifications of orgs the user still belongs to.
const notificationScope = `user_id = $1 AND org_id IN (SELECT id FROM user_organizations($1))`

func scanNotification(r pgx.CollectableRow) (notificationView, error) {
	var n notificationView
	return n, r.Scan(&n.ID, &n.OrgID, &n.AlertID, &n.Title, &n.Body, &n.Severity, &n.ReadAt, &n.CreatedAt)
}

const notificationColumns = `id, org_id, alert_id, title, body, severity::text, read_at, created_at`

func (rt *alertsRuntime) listNotifications(c *fiber.Ctx) error {
	user := authUser(c)
	pg, err := parsePage(c, false)
	if err != nil {
		return badPage(c, err)
	}
	ks := keyset{sort: "created_at", id: "id", desc: true}
	filter := ""
	if v := c.Query("unread"); v == "1" || v == "true" {
		filter = " AND read_at IS NULL"
	}
	var list []notificationView
	var total int64
	var capped bool
	err = withUser(c.Context(), rt.db, user, func(tx pgx.Tx) error {
		if total, capped, err = cappedCount(c.Context(), tx, `FROM notifications WHERE `+notificationScope+filter, []any{user}); err != nil {
			return err
		}
		cond, args, err := ks.where(pg, []any{user})
		if err != nil {
			return err
		}
		rows, err := tx.Query(c.Context(), `SELECT `+notificationColumns+` FROM notifications WHERE `+notificationScope+filter+
			cond+ks.orderLimit(pg), args...)
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, scanNotification)
		return err
	})
	if err != nil {
		return channelError(c, err)
	}
	items, next := page(list, pg.Limit, func(n notificationView) pageCursor { return timeCursor(n.CreatedAt, n.ID.String()) })
	return envelope(c, items, next, total, capped)
}

func (rt *alertsRuntime) readNotifications(c *fiber.Ctx) error {
	user := authUser(c)
	var in struct {
		IDs []uuid.UUID `json:"ids"`
		All bool        `json:"all"`
	}
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	if !in.All && len(in.IDs) == 0 {
		return badRequest(c, "ids or all is required")
	}
	if len(in.IDs) > 500 {
		return badRequest(c, "at most 500 ids")
	}
	var n int64
	err := withUser(c.Context(), rt.db, user, func(tx pgx.Tx) error {
		q := `UPDATE notifications SET read_at = NOW() WHERE user_id = $1 AND read_at IS NULL`
		args := []any{user}
		if !in.All {
			q += ` AND id = ANY($2)`
			args = append(args, in.IDs)
		}
		tag, err := tx.Exec(c.Context(), q, args...)
		n = tag.RowsAffected()
		return err
	})
	if err != nil {
		return serverError(c, err)
	}
	rt.hub.Publish(user) // other tabs refresh their count
	return c.JSON(fiber.Map{"updated": n})
}

// HeartbeatInterval of the SSE stream.
const HeartbeatInterval = 25 * time.Second

// stream is the SSE stream of the caller's notifications. Auth is the Bearer
// header (fetch-based EventSource), never a token in the URL. Events:
// "unread" {count} on connect and after changes, "notification" {...} for
// each new one. The session is checked again at every heartbeat.
func (rt *alertsRuntime) stream(c *fiber.Ctx) error {
	user := authUser(c)
	sess, hasSession := auth.CurrentSession(c)
	sub, unsubscribe, err := rt.hub.Subscribe(user)
	if err != nil {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": err.Error()})
	}
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache, no-transform")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")
	conn := c.Context().Conn()
	base := rt.base
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer unsubscribe()
		last := time.Now()
		sent := map[uuid.UUID]bool{}
		write := func(event string, data any) bool {
			_ = conn.SetWriteDeadline(time.Now().Add(HeartbeatInterval + 30*time.Second))
			if event == "" {
				_, _ = w.WriteString(": heartbeat\n\n")
			} else {
				raw, _ := json.Marshal(data)
				_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, raw)
			}
			return w.Flush() == nil
		}
		unread := func() (int64, error) {
			var n int64
			err := withUser(base, rt.db, user, func(tx pgx.Tx) error {
				return tx.QueryRow(base, `SELECT count(*) FROM notifications WHERE `+notificationScope+` AND read_at IS NULL`, user).Scan(&n)
			})
			return n, err
		}
		if n, err := unread(); err != nil || !write("unread", fiber.Map{"count": n}) {
			return
		}
		ticker := time.NewTicker(HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-base.Done():
				return
			case <-ticker.C:
				if hasSession && rt.sessions != nil {
					cctx, cancel := context.WithTimeout(base, 5*time.Second)
					_, err := rt.sessions.Lookup(cctx, sess.ID)
					cancel()
					if err != nil || time.Now().After(sess.ExpiresAt) {
						write("end", fiber.Map{"reason": "session ended"})
						return
					}
				}
				if !write("", nil) {
					return
				}
			case <-sub:
				var fresh []notificationView
				err := withUser(base, rt.db, user, func(tx pgx.Tx) error {
					rows, err := tx.Query(base, `SELECT `+notificationColumns+` FROM notifications WHERE `+notificationScope+
						` AND created_at > $2 ORDER BY created_at LIMIT 50`, user, last.Add(-time.Second))
					if err != nil {
						return err
					}
					fresh, err = pgx.CollectRows(rows, scanNotification)
					return err
				})
				if err != nil {
					return
				}
				if len(sent) > 1000 {
					clear(sent)
				}
				for _, n := range fresh {
					if sent[n.ID] {
						continue
					}
					sent[n.ID] = true
					if n.CreatedAt.After(last) {
						last = n.CreatedAt
					}
					if !write("notification", n) {
						return
					}
				}
				n, err := unread()
				if err != nil || !write("unread", fiber.Map{"count": n}) {
					return
				}
			}
		}
	})
	return nil
}
