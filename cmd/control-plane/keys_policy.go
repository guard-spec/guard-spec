// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// API key policy (migration 028): allowed addresses per key, the org's
// maximum key lifetime, and rotation with an overlap window.

const (
	maxKeyCIDRs            = 32
	maxKeyLifetimeDays     = 3650
	defaultRotationOverlap = 24 * time.Hour
	maxRotationOverlap     = 720 * time.Hour
)

// normalizeCIDRs validates allowed_cidrs: CIDRs or single addresses, at
// most maxKeyCIDRs, in canonical form.
func normalizeCIDRs(items []string) ([]string, error) {
	if len(items) > maxKeyCIDRs {
		return nil, fmt.Errorf("allowed_cidrs: at most %d entries", maxKeyCIDRs)
	}
	out := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		var canon string
		if strings.Contains(item, "/") {
			_, n, err := net.ParseCIDR(item)
			if err != nil {
				return nil, fmt.Errorf("allowed_cidrs: %q is not a CIDR", item)
			}
			canon = n.String()
		} else {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("allowed_cidrs: %q is not an IP address or CIDR", item)
			}
			canon = ip.String()
		}
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	return out, nil
}

var errKeyLifetime = errors.New("key lifetime")

// keyMaxLifetime reads the org's api_key_max_lifetime_days (0: none).
func keyMaxLifetime(ctx context.Context, tx pgx.Tx, org uuid.UUID) (int, error) {
	var days *int
	err := tx.QueryRow(ctx, `SELECT api_key_max_lifetime_days FROM org_security WHERE org_id = $1`, org).Scan(&days)
	if errors.Is(err, pgx.ErrNoRows) || days == nil {
		return 0, nil
	}
	return *days, err
}

// applyKeyLifetime checks an expiry against the org's maximum: an absent
// expiry becomes the latest allowed one, a later one is refused, and a past
// one is refused as well. Without a maximum, expires stays as given.
func applyKeyLifetime(expires *time.Time, maxDays int, now time.Time) (*time.Time, error) {
	if expires != nil && !expires.After(now) {
		return nil, fmt.Errorf("%w: expires_at must be in the future", errKeyLifetime)
	}
	if maxDays <= 0 {
		return expires, nil
	}
	latest := now.Add(time.Duration(maxDays) * 24 * time.Hour)
	if expires == nil {
		return &latest, nil
	}
	if expires.After(latest) {
		return nil, fmt.Errorf("%w: expires_at must be within %d days (the organization's maximum key lifetime)", errKeyLifetime, maxDays)
	}
	return expires, nil
}

// newRawKey makes a key: gs_<32 hex>, its hash and its prefix.
func newRawKey() (raw, hash, prefix string, err error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", err
	}
	raw = "gs_" + hex.EncodeToString(buf)
	return raw, tenant.HashKey(raw), raw[:11], nil
}

var (
	errKeyNotFound = errors.New("not found")
	errKeyRevoked  = errors.New("the key is revoked")
	errKeyRotated  = errors.New("the key was already rotated; rotate its successor instead")
)

// rotateAPIKey answers POST .../api-keys/:keyId/rotate {overlap_hours,
// expires_at}: a successor key with the same alias, project, limits and
// allowed addresses, shown once; the old key keeps working for the overlap
// (default 24 hours, at most 720) and then expires. expires_at is the
// successor's, within the org's maximum lifetime.
func rotateAPIKey(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		oldPrefix := c.Params("keyId")
		var req struct {
			OverlapHours *float64   `json:"overlap_hours"`
			ExpiresAt    *time.Time `json:"expires_at"`
		}
		if len(c.Body()) > 0 {
			if err := json.Unmarshal(c.Body(), &req); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "invalid body: " + err.Error()})
			}
		}
		overlap := defaultRotationOverlap
		if req.OverlapHours != nil {
			overlap = time.Duration(*req.OverlapHours * float64(time.Hour))
			if overlap < 0 || overlap > maxRotationOverlap {
				return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("overlap_hours must be between 0 and %d", int(maxRotationOverlap.Hours()))})
			}
		}
		raw, hash, prefix, err := newRawKey()
		if err != nil {
			return serverError(c, err)
		}
		now := time.Now()
		var (
			alias     *string
			projectID *uuid.UUID
			expires   *time.Time
			oldExpiry time.Time
			cidrs     []string
		)
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var revoked, rotatedAt *time.Time
			var rotatedTo *string
			var oldExpires *time.Time
			var budget *uuid.UUID
			var rpm *int32
			var tpm, rpd *int64
			err := tx.QueryRow(c.Context(),
				`SELECT alias, project_id, budget_id, rpm_limit, tpm_limit, rpd_limit, allowed_cidrs, expires_at, revoked_at, rotated_to, rotated_at
				 FROM api_keys WHERE key_prefix = $1 AND org_id = $2 FOR UPDATE`, oldPrefix, org).
				Scan(&alias, &projectID, &budget, &rpm, &tpm, &rpd, &cidrs, &oldExpires, &revoked, &rotatedTo, &rotatedAt)
			if errors.Is(err, pgx.ErrNoRows) {
				return errKeyNotFound
			}
			if err != nil {
				return err
			}
			if revoked != nil {
				return errKeyRevoked
			}
			if rotatedTo != nil {
				return errKeyRotated
			}
			maxDays, err := keyMaxLifetime(c.Context(), tx, org)
			if err != nil {
				return err
			}
			if expires, err = applyKeyLifetime(req.ExpiresAt, maxDays, now); err != nil {
				return err
			}
			if cidrs == nil {
				cidrs = []string{}
			}
			if _, err := tx.Exec(c.Context(),
				`INSERT INTO api_keys (key_hash, key_prefix, alias, org_id, project_id, budget_id, rpm_limit, tpm_limit, rpd_limit,
				   allowed_cidrs, expires_at, created_by)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
				hash, prefix, alias, org, projectID, budget, rpm, tpm, rpd, cidrs, expires, nullUUID(auth.UserID(c))); err != nil {
				return err
			}
			// The old key ends at the overlap, or sooner when it already would.
			oldExpiry = now.Add(overlap)
			if oldExpires != nil && oldExpires.Before(oldExpiry) {
				oldExpiry = *oldExpires
			}
			_, err = tx.Exec(c.Context(),
				`UPDATE api_keys SET expires_at = $3, rotated_to = $4, rotated_at = NOW(), last_rotation_at = NOW()
				 WHERE key_prefix = $1 AND org_id = $2`, oldPrefix, org, oldExpiry, prefix)
			return err
		})
		switch {
		case errors.Is(err, errKeyNotFound):
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		case errors.Is(err, errKeyRevoked), errors.Is(err, errKeyRotated):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		case errors.Is(err, errKeyLifetime):
			return c.Status(400).JSON(fiber.Map{"error": strings.TrimPrefix(err.Error(), "key lifetime: ")})
		case err != nil:
			return serverError(c, err)
		}
		logActivity(c, db, &org, "api_key.rotated", oldPrefix, map[string]any{
			"successor": prefix, "old_expires_at": oldExpiry, "overlap_hours": overlap.Hours(), "alias": alias})
		return c.Status(201).JSON(fiber.Map{
			"key":            raw,
			"key_prefix":     prefix,
			"alias":          alias,
			"project_id":     projectID,
			"expires_at":     expires,
			"allowed_cidrs":  cidrs,
			"rotated_from":   oldPrefix,
			"old_expires_at": oldExpiry,
		})
	}
}

// updateAPIKey changes a key's rate limits, allowed addresses (migration
// 028) and expiry; absent fields are kept. expires_at null removes the
// expiry, which the org's maximum key lifetime refuses.
func updateAPIKey(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			RPMLimit     optLimit  `json:"rpm_limit"`
			TPMLimit     optLimit  `json:"tpm_limit"`
			AllowedCIDRs *[]string `json:"allowed_cidrs"`
			ExpiresAt    optTime   `json:"expires_at"`
		}
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if !req.RPMLimit.Set && !req.TPMLimit.Set && req.AllowedCIDRs == nil && !req.ExpiresAt.Set {
			return c.Status(400).JSON(fiber.Map{"error": "rpm_limit, tpm_limit, allowed_cidrs or expires_at is required"})
		}
		var cidrs []string
		if req.AllowedCIDRs != nil {
			var err error
			if cidrs, err = normalizeCIDRs(*req.AllowedCIDRs); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": err.Error()})
			}
		}
		var rpm *int64
		var tpm *int64
		var expires *time.Time
		var gotCIDRs []string
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			expiresVal := req.ExpiresAt.Value
			if req.ExpiresAt.Set {
				maxDays, err := keyMaxLifetime(c.Context(), tx, org)
				if err != nil {
					return err
				}
				if maxDays > 0 && expiresVal == nil {
					return fmt.Errorf("%w: expires_at is required (the organization's maximum key lifetime is %d days)", errKeyLifetime, maxDays)
				}
				if expiresVal, err = applyKeyLifetime(expiresVal, maxDays, time.Now()); err != nil {
					return err
				}
			}
			return tx.QueryRow(c.Context(),
				`UPDATE api_keys SET
				   rpm_limit = CASE WHEN $1 THEN $2::int ELSE rpm_limit END,
				   tpm_limit = CASE WHEN $3 THEN $4::bigint ELSE tpm_limit END,
				   allowed_cidrs = CASE WHEN $7 THEN $8::text[] ELSE allowed_cidrs END,
				   expires_at = CASE WHEN $9 THEN $10::timestamptz ELSE expires_at END
				 WHERE key_prefix = $5 AND org_id = $6 AND revoked_at IS NULL
				 RETURNING rpm_limit::bigint, tpm_limit, allowed_cidrs, expires_at`,
				req.RPMLimit.Set, req.RPMLimit.Value, req.TPMLimit.Set, req.TPMLimit.Value,
				c.Params("keyId"), org, req.AllowedCIDRs != nil, cidrs, req.ExpiresAt.Set, expiresVal).
				Scan(&rpm, &tpm, &gotCIDRs, &expires)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		if errors.Is(err, errKeyLifetime) {
			return c.Status(400).JSON(fiber.Map{"error": strings.TrimPrefix(err.Error(), "key lifetime: ")})
		}
		if err != nil {
			return serverError(c, err)
		}
		if gotCIDRs == nil {
			gotCIDRs = []string{}
		}
		logActivity(c, db, &org, "api_key.updated", c.Params("keyId"), map[string]any{"rpm_limit": rpm, "tpm_limit": tpm,
			"allowed_cidrs": gotCIDRs, "expires_at": expires})
		return c.JSON(fiber.Map{"key_prefix": c.Params("keyId"), "rpm_limit": rpm, "tpm_limit": tpm,
			"allowed_cidrs": gotCIDRs, "expires_at": expires})
	}
}

// optTime is a time that may be absent (Set false) or null (Value nil).
type optTime struct {
	Set   bool
	Value *time.Time
}

func (o *optTime) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.Value = nil
		return nil
	}
	var v time.Time
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	o.Value = &v
	return nil
}
