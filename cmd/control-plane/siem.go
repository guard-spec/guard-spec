// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/guard-spec/guard-spec/internal/alerts"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/events"
	secretsrc "github.com/guard-spec/guard-spec/internal/secrets"
	"github.com/guard-spec/guard-spec/internal/siem"
	"github.com/guard-spec/guard-spec/internal/tenant"
)

// SIEM export (docs/siem.md): an organization's sinks, which the export
// worker (internal/siem) feeds with the org's events as OCSF records. Admins
// manage them; the secret is a variable name (SIEM_*), bound to the org by
// the operator in ALERTS_SECRET_ORGS (kind siem); private addresses need
// ALERTS_PRIVATE_ORGS, as for alert channels.

// siemResolver resolves sink secrets and private-address permission.
type siemResolver struct {
	secretOrgs  alerts.SecretOrgs
	privateOrgs alerts.PrivateOrgs
	getenv      func(string) string
}

func (r siemResolver) Secret(org uuid.UUID, env string) (string, error) {
	if err := alerts.CheckSecretEnv(alerts.KindSIEM, env, org, r.secretOrgs); err != nil {
		return "", err
	}
	v := r.getenv(env)
	if v == "" {
		return "", errors.New(env + " is not set in the control plane's environment")
	}
	return v, nil
}

func (r siemResolver) AllowPrivate(org uuid.UUID, asked bool) bool {
	return asked && r.privateOrgs[org.String()]
}

func newSIEMResolver(cfg *alertsConfig) siemResolver {
	r := siemResolver{getenv: secretsrc.Getenv}
	if cfg != nil {
		r.secretOrgs, r.privateOrgs = cfg.secretOrgs, cfg.privateOrgs
		if cfg.getenv != nil {
			r.getenv = cfg.getenv
		}
	}
	return r
}

type siemSinkBody struct {
	Name         string         `json:"name"`
	Kind         string         `json:"kind"`
	Config       map[string]any `json:"config"`
	SecretEnv    *string        `json:"secret_env"`
	EventTypes   []string       `json:"event_types"`
	MinSeverity  string         `json:"min_severity"`
	AllowPrivate bool           `json:"allow_private"`
	Enabled      *bool          `json:"enabled"`
}

type siemSinkRow struct {
	ID            uuid.UUID      `json:"id"`
	Name          string         `json:"name"`
	Kind          string         `json:"kind"`
	Config        map[string]any `json:"config"`
	SecretEnv     *string        `json:"secret_env"`
	SecretSet     bool           `json:"secret_set"`
	EventTypes    []string       `json:"event_types"`
	MinSeverity   string         `json:"min_severity"`
	AllowPrivate  bool           `json:"allow_private"`
	Enabled       bool           `json:"enabled"`
	CursorAt      time.Time      `json:"cursor_at"`
	Failures      int            `json:"failures"`
	LastError     *string        `json:"last_error"`
	LastSuccessAt *time.Time     `json:"last_success_at"`
	Delivered     int64          `json:"delivered"`
	CreatedAt     time.Time      `json:"created_at"`
}

const siemColumns = `id, name, kind, config, secret_env, event_types, min_severity::text, allow_private, enabled,
	cursor_at, failures, last_error, last_success_at, delivered, created_at`

const siemSelect = `SELECT ` + siemColumns + ` FROM siem_sinks`

func scanSink(row pgx.Row, r siemResolver) (siemSinkRow, error) {
	var s siemSinkRow
	err := row.Scan(&s.ID, &s.Name, &s.Kind, &s.Config, &s.SecretEnv, &s.EventTypes, &s.MinSeverity, &s.AllowPrivate,
		&s.Enabled, &s.CursorAt, &s.Failures, &s.LastError, &s.LastSuccessAt, &s.Delivered, &s.CreatedAt)
	if s.SecretEnv != nil {
		s.SecretSet = r.getenv(*s.SecretEnv) != ""
	}
	if s.EventTypes == nil {
		s.EventTypes = []string{}
	}
	return s, err
}

// validate checks a sink body for org; the error is safe to show.
func (b *siemSinkBody) validate(org uuid.UUID, r siemResolver) error {
	b.Name = strings.TrimSpace(b.Name)
	if b.Name == "" || len([]rune(b.Name)) > 100 {
		return errors.New("name must be 1 to 100 characters")
	}
	if b.Config == nil {
		b.Config = map[string]any{}
	}
	for k, v := range b.Config {
		if _, ok := v.(string); !ok {
			return errors.New("config." + k + " must be a string")
		}
	}
	if b.MinSeverity == "" {
		b.MinSeverity = events.Info
	}
	if b.MinSeverity != events.Info && b.MinSeverity != events.Warning && b.MinSeverity != events.Critical {
		return errors.New("min_severity must be info, warning or critical")
	}
	for _, t := range b.EventTypes {
		if len(t) == 0 || len(t) > 80 || strings.ContainsAny(t, " \t,") {
			return errors.New("event_types holds types such as detection.blocked, or families such as detection. ending with a dot")
		}
	}
	if b.SecretEnv != nil && *b.SecretEnv == "" {
		b.SecretEnv = nil
	}
	if b.SecretEnv != nil {
		if err := alerts.CheckSecretEnv(alerts.KindSIEM, *b.SecretEnv, org, r.secretOrgs); err != nil {
			return err
		}
	}
	if b.AllowPrivate && !r.privateOrgs[org.String()] {
		return errors.New("allow_private needs this organization in ALERTS_PRIVATE_ORGS")
	}
	return siem.Sink{Kind: b.Kind, Config: b.Config, AllowPrivate: b.AllowPrivate}.Validate()
}

func registerSIEMRoutes(authed fiber.Router, db *pgxpool.Pool, r siemResolver) {
	admin := auth.RequireRole(db, auth.RoleAdmin)
	base := "/organizations/:orgId/siem-sinks"

	authed.Get(base, admin, func(c *fiber.Ctx) error {
		org := orgID(c)
		out := []siemSinkRow{}
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(), siemSelect+` WHERE org_id = $1 ORDER BY created_at`, org)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				s, err := scanSink(rows, r)
				if err != nil {
					return err
				}
				out = append(out, s)
			}
			return rows.Err()
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"data": out, "kinds": siem.Kinds, "ocsf_version": siem.OCSFVersion})
	})

	authed.Post(base, admin, func(c *fiber.Ctx) error {
		org := orgID(c)
		var b siemSinkBody
		if err := json.Unmarshal(c.Body(), &b); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if err := b.validate(org, r); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		enabled := b.Enabled == nil || *b.Enabled
		var out siemSinkRow
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			out, err = scanSink(tx.QueryRow(c.Context(), `INSERT INTO siem_sinks (org_id, name, kind, config, secret_env,
				event_types, min_severity, allow_private, enabled) VALUES ($1,$2,$3,$4,$5,$6,$7::alert_severity,$8,$9)
				RETURNING `+siemColumns,
				org, b.Name, b.Kind, b.Config, b.SecretEnv, nullList(b.EventTypes), b.MinSeverity, b.AllowPrivate, enabled), r)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "siem_sink.created", out.ID.String(), map[string]any{"name": out.Name, "kind": out.Kind})
		return c.Status(201).JSON(out)
	})

	authed.Put(base+"/:id", admin, func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
		}
		var b siemSinkBody
		if err := json.Unmarshal(c.Body(), &b); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if err := b.validate(org, r); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		enabled := b.Enabled == nil || *b.Enabled
		var out siemSinkRow
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			// Turning a sink on again makes it due now and clears the backoff;
			// the cursor stays, so it catches up.
			tag, err := tx.Exec(c.Context(), `UPDATE siem_sinks SET name = $3, kind = $4, config = $5, secret_env = $6,
				event_types = $7, min_severity = $8::alert_severity, allow_private = $9, enabled = $10,
				failures = 0, last_error = NULL, next_attempt_at = NOW(), updated_at = NOW()
				WHERE org_id = $1 AND id = $2`, org, id, b.Name, b.Kind, b.Config, b.SecretEnv, nullList(b.EventTypes),
				b.MinSeverity, b.AllowPrivate, enabled)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return pgx.ErrNoRows
			}
			out, err = scanSink(tx.QueryRow(c.Context(), siemSelect+` WHERE org_id = $1 AND id = $2`, org, id), r)
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "sink not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "siem_sink.updated", id.String(), map[string]any{"name": out.Name, "kind": out.Kind, "enabled": out.Enabled})
		return c.JSON(out)
	})

	authed.Delete(base+"/:id", admin, func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
		}
		var n int64
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			tag, err := tx.Exec(c.Context(), `DELETE FROM siem_sinks WHERE org_id = $1 AND id = $2`, org, id)
			n = tag.RowsAffected()
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		if n == 0 {
			return c.Status(404).JSON(fiber.Map{"error": "sink not found"})
		}
		logActivity(c, db, &org, "siem_sink.deleted", id.String(), nil)
		return c.SendStatus(204)
	})

	authed.Post(base+"/:id/test", admin, func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
		}
		var st siem.Stored
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			st, err = siem.Load(c.Context(), tx, org, id)
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "sink not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		sink, err := st.Sink(r)
		if err == nil {
			err = siem.Test(c.Context(), sink, org, auth.UserID(c).String())
		}
		if err != nil {
			return c.JSON(fiber.Map{"ok": false, "error": err.Error()})
		}
		return c.JSON(fiber.Map{"ok": true})
	})
}

func nullList(l []string) []string {
	if len(l) == 0 {
		return nil
	}
	return l
}
