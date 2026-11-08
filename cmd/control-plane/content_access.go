// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/datakey"
	"github.com/guard-spec/guard-spec/internal/tenant"
)

// Reading stored content (RF-aceaddfc). The request log lists rows with
// has_content only; the prompt and the answer of one row come from
// POST /v1/organizations/{org}/requests/{id}/content, which
//
//   - needs the org's content_read_role (security policy, default admin);
//   - needs {"reason": "..."} when content_view_reason is on (the default),
//     3 to 500 characters;
//   - writes request.content_viewed to the activity log with the reason,
//     before the content is returned, whether it opens or not.

const (
	minReasonLen = 3
	maxReasonLen = 500
)

func readRequestContent(db *pgxpool.Pool, keys *datakey.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		reqID, err := uuid.Parse(c.Params("requestId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request id"})
		}
		sec, err := loadOrgSecurity(c.Context(), db, org)
		if err != nil {
			return serverError(c, err)
		}
		min, _ := auth.ParseRole(sec.ContentReadRole)
		if !auth.HasRole(auth.CallerRole(c), min) {
			return auth.Deny(c, fiber.StatusForbidden, "content_read_role",
				"reading stored content needs the "+sec.ContentReadRole+" role in this organization")
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if len(c.Body()) > 0 {
			if err := c.BodyParser(&body); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
			}
		}
		reason := strings.TrimSpace(body.Reason)
		if n := utf8.RuneCountInString(reason); sec.ContentViewReason != nil && *sec.ContentViewReason && n < minReasonLen {
			return c.Status(400).JSON(fiber.Map{"error": "give a reason for reading this content (at least 3 characters)",
				"code": "reason_required"})
		}
		if utf8.RuneCountInString(reason) > maxReasonLen {
			return c.Status(400).JSON(fiber.Map{"error": "the reason is longer than 500 characters"})
		}
		var out struct {
			RequestContent  *string `json:"request_content"`
			ResponseContent *string `json:"response_content"`
			ContentError    string  `json:"content_error,omitempty"`
		}
		var reqSHA, respSHA *string
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(), `SELECT request_sha256, request_content, response_sha256, response_content
				FROM requests WHERE org_id = $1 AND id = $2`, org, reqID).
				Scan(&reqSHA, &out.RequestContent, &respSHA, &out.ResponseContent)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "request not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		if out.RequestContent == nil && out.ResponseContent == nil {
			return c.Status(404).JSON(fiber.Map{"error": "this request has no stored content", "code": "no_content"})
		}
		details := map[string]any{}
		if reason != "" {
			details["reason"] = reason
		}
		// "request <id>": the activity page shows a target that is not a bare id.
		logActivity(c, db, &org, "request.content_viewed", "request "+reqID.String(), details)
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			out.ContentError = openContent(c.Context(), tx, keys, org,
				contentField{&out.RequestContent, "request_content", reqSHA},
				contentField{&out.ResponseContent, "response_content", respSHA})
			return nil
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(out)
	}
}
