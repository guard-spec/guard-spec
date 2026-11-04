// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/mail"
	"strings"
	"time"

	"github.com/giaplee/guard-spec/internal/alerts/channels"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
)

// The personal email address: PUT sends a code to the new address, and the
// address replaces the account address only once the code comes back
// (double opt-in), so nobody can point alerts at a third party's mailbox.

const (
	emailCodeTTL      = 30 * time.Minute
	emailCodeAttempts = 5
	emailCodeInterval = time.Minute // between two codes of one user
	emailCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

func emailCode() (string, error) {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(emailCodeAlphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(emailCodeAlphabet[n.Int64()])
	}
	return b.String(), nil
}

var errCodeTooSoon = errors.New("a code was sent less than a minute ago")

// emailLink starts the change of the personal email address:
// PUT /v1/me/channel-links/email {address} → 202 {address, verified:false, expires_at}.
func (rt *alertsRuntime) emailLink(c *fiber.Ctx) error {
	if !rt.cfg.smtp.Enabled() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "SMTP is not configured on this instance"})
	}
	user := authUser(c)
	var in struct {
		Address string `json:"address"`
	}
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	raw := strings.TrimSpace(in.Address)
	addr, err := mail.ParseAddress(raw)
	if err != nil || addr.Address != raw || len(raw) > 320 {
		return badRequest(c, "address must be an email address")
	}
	raw = strings.ToLower(raw)
	code, err := emailCode()
	if err != nil {
		return serverError(c, err)
	}
	expires := time.Now().Add(emailCodeTTL).UTC()
	err = withUser(c.Context(), rt.db, user, func(tx pgx.Tx) error {
		var last *time.Time
		if err := tx.QueryRow(c.Context(), `SELECT created_at FROM email_link_codes WHERE user_id = $1`, user).
			Scan(&last); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if last != nil && time.Since(*last) < emailCodeInterval {
			return errCodeTooSoon
		}
		_, err := tx.Exec(c.Context(),
			`INSERT INTO email_link_codes (user_id, address, code_hash, expires_at) VALUES ($1, $2, $3, $4)
			 ON CONFLICT (user_id) DO UPDATE SET address = EXCLUDED.address, code_hash = EXCLUDED.code_hash,
			   attempts = 0, expires_at = EXCLUDED.expires_at, created_at = NOW()`,
			user, raw, hashCode(code), expires)
		return err
	})
	if errors.Is(err, errCodeTooSoon) {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": err.Error()})
	}
	if err != nil {
		return serverError(c, err)
	}
	subject, body := "[Guard Spec] Your confirmation code", "Your Guard Spec confirmation code is "+code+
		".\n\nEnter it under My account > Notifications within 30 minutes to receive alerts at this address.\n"+
		"If you did not ask for it, ignore this mail.\n"
	if rt.cfg.lang == "vi" {
		subject, body = "[Guard Spec] Mã xác nhận", "Mã xác nhận Guard Spec của bạn là "+code+
			".\n\nNhập mã tại Tài khoản của tôi > Thông báo trong 30 phút để nhận cảnh báo tại địa chỉ này.\n"+
			"Nếu bạn không yêu cầu, hãy bỏ qua thư này.\n"
	}
	ctx, cancel := context.WithTimeout(c.Context(), 2*channels.Timeout)
	defer cancel()
	if err := (&channels.Email{SMTP: rt.cfg.smtp}).SendText(ctx, raw, subject, body); err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "the confirmation mail could not be sent"})
	}
	logUserEvent(c.Context(), rt.db, user, "alerts.link.email_code_sent", clientIP(c), nil)
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"kind": "email", "address": raw, "verified": false,
		"expires_at": expires})
}

// emailLinkConfirm finishes it: POST /v1/me/channel-links/email/confirm {code}.
func (rt *alertsRuntime) emailLinkConfirm(c *fiber.Ctx) error {
	user := authUser(c)
	var in struct {
		Code string `json:"code"`
	}
	if err := strictJSON(c.Body(), &in); err != nil {
		return badRequest(c, err.Error())
	}
	code := strings.ToUpper(strings.TrimSpace(in.Code))
	var l linkView
	var bad bool
	err := withUser(c.Context(), rt.db, user, func(tx pgx.Tx) error {
		var address, hash string
		var attempts int
		var expires time.Time
		err := tx.QueryRow(c.Context(),
			`SELECT address, code_hash, attempts, expires_at FROM email_link_codes WHERE user_id = $1 FOR UPDATE`, user).
			Scan(&address, &hash, &attempts, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			bad = true
			return nil
		}
		if err != nil {
			return err
		}
		if attempts >= emailCodeAttempts || time.Now().After(expires) {
			bad = true
			_, err := tx.Exec(c.Context(), `DELETE FROM email_link_codes WHERE user_id = $1`, user)
			return err
		}
		if hashCode(code) != hash {
			bad = true
			_, err := tx.Exec(c.Context(), `UPDATE email_link_codes SET attempts = attempts + 1 WHERE user_id = $1`, user)
			return err
		}
		if _, err := tx.Exec(c.Context(), `DELETE FROM email_link_codes WHERE user_id = $1`, user); err != nil {
			return err
		}
		return tx.QueryRow(c.Context(),
			`INSERT INTO user_channel_links (user_id, kind, address, verified_at) VALUES ($1, 'email', $2, NOW())
			 ON CONFLICT (user_id, kind) DO UPDATE SET address = EXCLUDED.address, verified_at = NOW()
			 RETURNING kind, address, verified_at, created_at`, user, address).
			Scan(&l.Kind, &l.Address, &l.VerifiedAt, &l.CreatedAt)
	})
	if err != nil {
		return serverError(c, err)
	}
	if bad {
		return badRequest(c, "the code is wrong, expired or used up; ask for a new one")
	}
	l.Verified = true
	logUserEvent(c.Context(), rt.db, user, "alerts.link.created", clientIP(c), map[string]any{"kind": "email"})
	return c.JSON(l)
}
