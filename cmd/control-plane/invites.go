package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/giaplee/guard-spec/internal/auth"
	"github.com/giaplee/guard-spec/internal/tenant"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultInviteTTL = 72 * time.Hour
	maxInviteTTL     = 30 * 24 * time.Hour
	invitePrefix     = "gsinv_"
	minPasswordLen   = 12
	maxPasswordLen   = 72 // bcrypt ignores anything longer
)

// Invite flow: an admin creates an invite for an email and a role and gets a
// one-time token back (no email is sent; the admin passes the token on). The
// invitee posts the token and a password to /v1/invites/accept, which creates
// the user, or adds the membership to an existing user whose password matches.
// Only the token's SHA-256 is stored.

type inviteRow struct {
	ID         uuid.UUID  `json:"id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Status     string     `json:"status"` // pending, accepted, revoked, expired
	InvitedBy  *uuid.UUID `json:"invited_by"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

func createInvite(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			Email    string `json:"email"`
			Role     string `json:"role"`
			TTLHours *int   `json:"ttl_hours"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		email := strings.ToLower(strings.TrimSpace(req.Email))
		if len(email) > 254 || strings.Count(email, "@") != 1 || strings.HasPrefix(email, "@") ||
			strings.HasSuffix(email, "@") {
			return c.Status(400).JSON(fiber.Map{"error": "a valid email is required"})
		}
		if req.Role == "" {
			req.Role = string(auth.RoleMember)
		}
		role, ok := auth.ParseRole(req.Role)
		if !ok {
			return c.Status(400).JSON(fiber.Map{"error": "role must be viewer, member, admin or owner"})
		}
		// Nobody hands out more than they have: an admin cannot create owners.
		if !auth.HasRole(auth.CallerRole(c), role) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "cannot invite with a role above your own"})
		}
		ttl := defaultInviteTTL
		if req.TTLHours != nil {
			ttl = time.Duration(*req.TTLHours) * time.Hour
			if ttl <= 0 || ttl > maxInviteTTL {
				return c.Status(400).JSON(fiber.Map{"error": "ttl_hours must be between 1 and 720"})
			}
		}

		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return serverError(c, err)
		}
		token := invitePrefix + hex.EncodeToString(buf)
		inv := inviteRow{ID: uuid.New(), Email: email, Role: string(role), Status: "pending"}
		inviter := auth.UserID(c)
		inv.InvitedBy = &inviter
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(),
				`INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
				 VALUES ($1, $2, $3, $4, $5, $6, NOW() + $7::interval)
				 RETURNING expires_at, created_at`,
				inv.ID, org, email, string(role), tenant.HashKey(token), inviter, ttl).
				Scan(&inv.ExpiresAt, &inv.CreatedAt)
		})
		if err != nil {
			return serverError(c, err)
		}
		slog.Info("invite created", "org", org, "invite", inv.ID, "role", role, "by", inviter)
		// The token is shown once only.
		return c.Status(201).JSON(fiber.Map{
			"id": inv.ID, "email": inv.Email, "role": inv.Role,
			"expires_at": inv.ExpiresAt, "created_at": inv.CreatedAt, "token": token,
		})
	}
}

func listInvites(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		invites := []inviteRow{}
		err := tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			rows, err := tx.Query(c.Context(),
				`SELECT id, email, role::text, invited_by, expires_at, accepted_at, revoked_at, created_at,
				        CASE WHEN accepted_at IS NOT NULL THEN 'accepted'
				             WHEN revoked_at IS NOT NULL THEN 'revoked'
				             WHEN expires_at <= NOW() THEN 'expired'
				             ELSE 'pending' END
				 FROM invites WHERE org_id = $1 ORDER BY created_at DESC LIMIT 1000`, org)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var r inviteRow
				if err := rows.Scan(&r.ID, &r.Email, &r.Role, &r.InvitedBy, &r.ExpiresAt, &r.AcceptedAt,
					&r.RevokedAt, &r.CreatedAt, &r.Status); err != nil {
					return err
				}
				invites = append(invites, r)
			}
			return rows.Err()
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"data": invites})
	}
}

func revokeInvite(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("inviteId"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid invite id"})
		}
		var n int64
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			tag, err := tx.Exec(c.Context(),
				`UPDATE invites SET revoked_at = NOW()
				 WHERE id = $1 AND org_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL`, id, org)
			n = tag.RowsAffected()
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		if n == 0 {
			return c.Status(404).JSON(fiber.Map{"error": "no pending invite with this id"})
		}
		slog.Info("invite revoked", "org", org, "invite", id, "by", auth.UserID(c))
		return c.Status(204).Send(nil)
	}
}

var (
	errInviteInvalid  = errors.New("invalid, expired or already used invite")
	errAlreadyMember  = errors.New("already a member of this organization")
	errWrongPassword  = errors.New("an account with this email exists; use its password to accept")
	errDuplicateEmail = errors.New("duplicate email")
)

// acceptInvite needs no session: the token is the credential.
func acceptInvite(db *pgxpool.Pool, secret []byte) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Token       string `json:"token"`
			Password    string `json:"password"`
			DisplayName string `json:"display_name"`
		}
		if err := c.BodyParser(&req); err != nil || req.Token == "" {
			return c.Status(400).JSON(fiber.Map{"error": "token and password are required"})
		}
		if len(req.Password) < minPasswordLen || len(req.Password) > maxPasswordLen {
			return c.Status(400).JSON(fiber.Map{"error": "password must be 12 to 72 bytes long"})
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			return serverError(c, err)
		}
		ctx := c.Context()
		var userID, org uuid.UUID
		var role string
		err = pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			var inviteID uuid.UUID
			var email string
			var inviter *uuid.UUID
			err := tx.QueryRow(ctx, `SELECT invite_id, org_id, email, role::text FROM claim_invite($1)`,
				tenant.HashKey(req.Token)).Scan(&inviteID, &org, &email, &role)
			if errors.Is(err, pgx.ErrNoRows) {
				return errInviteInvalid
			}
			if err != nil {
				return err
			}
			// Everything after the claim is scoped to the invite's org.
			if _, err := tx.Exec(ctx, `SELECT set_config('app.org_id', $1, true)`, org.String()); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT invited_by FROM invites WHERE id = $1`, inviteID).
				Scan(&inviter); err != nil {
				return err
			}
			var stored *string
			err = tx.QueryRow(ctx, `SELECT id, hashed_password FROM users WHERE email = $1`, email).
				Scan(&userID, &stored)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				var display *string
				if d := strings.TrimSpace(req.DisplayName); d != "" {
					display = &d
				}
				err = tx.QueryRow(ctx,
					`INSERT INTO users (email, display_name, hashed_password) VALUES ($1, $2, $3) RETURNING id`,
					email, display, hash).Scan(&userID)
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" {
					return errDuplicateEmail // created concurrently
				}
				if err != nil {
					return err
				}
			case err != nil:
				return err
			default:
				h := ""
				if stored != nil {
					h = *stored
				}
				if !auth.CheckPassword(h, req.Password) {
					return errWrongPassword
				}
			}
			tag, err := tx.Exec(ctx,
				`INSERT INTO org_memberships (user_id, org_id, role, invited_by) VALUES ($1, $2, $3::org_role, $4)
				 ON CONFLICT (user_id, org_id) DO NOTHING`, userID, org, role, inviter)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return errAlreadyMember
			}
			_, err = tx.Exec(ctx, `UPDATE invites SET accepted_by = $1 WHERE id = $2`, userID, inviteID)
			return err
		})
		switch {
		case errors.Is(err, errInviteInvalid):
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": errInviteInvalid.Error()})
		case errors.Is(err, errWrongPassword):
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": errWrongPassword.Error()})
		case errors.Is(err, errAlreadyMember):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": errAlreadyMember.Error()})
		case errors.Is(err, errDuplicateEmail):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "an account with this email was just created; try again"})
		case err != nil:
			return serverError(c, err)
		}
		token, err := auth.IssueToken(secret, userID)
		if err != nil {
			return serverError(c, err)
		}
		slog.Info("invite accepted", "org", org, "user", userID, "role", role)
		return c.Status(201).JSON(fiber.Map{"user_id": userID, "org_id": org, "role": role, "token": token})
	}
}
