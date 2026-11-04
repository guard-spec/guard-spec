// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/mail"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
)

// emailLink sets the address personal email alerts go to (instead of the
// account address). The address is not confirmed by a mail, so it must be in
// the account email's domain: nobody can point alerts at a third party's
// mailbox.
func (rt *alertsRuntime) emailLink(c *fiber.Ctx) error {
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
	var account string
	if err := rt.db.QueryRow(c.Context(), `SELECT email FROM users WHERE id = $1`, user).Scan(&account); err != nil {
		return serverError(c, err)
	}
	if !strings.EqualFold(emailDomain(raw), emailDomain(account)) {
		return badRequest(c, "the address must be in the domain of your account email ("+emailDomain(account)+")")
	}
	var l linkView
	err = withUser(c.Context(), rt.db, user, func(tx pgx.Tx) error {
		return tx.QueryRow(c.Context(),
			`INSERT INTO user_channel_links (user_id, kind, address, verified_at) VALUES ($1, 'email', $2, NOW())
			 ON CONFLICT (user_id, kind) DO UPDATE SET address = EXCLUDED.address, verified_at = NOW()
			 RETURNING kind, address, verified_at, created_at`, user, strings.ToLower(raw)).
			Scan(&l.Kind, &l.Address, &l.VerifiedAt, &l.CreatedAt)
	})
	if err != nil {
		return serverError(c, err)
	}
	logUserEvent(c.Context(), rt.db, user, "alerts.link.created", clientIP(c), map[string]any{"kind": "email"})
	return c.JSON(l)
}
