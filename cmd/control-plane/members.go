package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// User management: an organization's members, project roles, and the
// instance's users (instance administrators only).
//
// Rules on org roles, enforced here and not only in the UI:
//   - nobody grants a role above their own: an admin cannot make owners;
//   - an admin cannot change or remove an owner;
//   - the last owner can be neither demoted nor removed (409).

type memberRow struct {
	UserID       uuid.UUID  `json:"user_id"`
	Email        string     `json:"email"`
	DisplayName  *string    `json:"display_name"`
	Role         string     `json:"role"`
	MFAEnabled   bool       `json:"mfa_enabled"`
	LoginMethods []string   `json:"login_methods"`
	LastLoginAt  *time.Time `json:"last_login_at"`
	JoinedAt     time.Time  `json:"joined_at"`
	Disabled     bool       `json:"disabled"`
}

// loginMethodsSQL lists a user's login methods: password, google, oidc:<id>, saml:<id>.
const loginMethodsSQL = `ARRAY(
	SELECT 'password' WHERE u.hashed_password IS NOT NULL
	UNION ALL
	SELECT DISTINCT CASE p.type WHEN 'google' THEN 'google' WHEN 'saml' THEN 'saml:' || p.id::text ELSE 'oidc:' || p.id::text END
	FROM user_identities i JOIN identity_providers p ON p.id = i.provider_id WHERE i.user_id = u.id)`

const mfaEnabledSQL = `EXISTS (SELECT 1 FROM user_mfa mf WHERE mf.user_id = u.id AND mf.enabled_at IS NOT NULL)`

func listMembers(db *pgxpool.Pool) fiber.Handler {
	ks := keyset{sort: "m.joined_at", id: "m.user_id"}
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		pg, err := parsePage(c, false)
		if err != nil {
			return badPage(c, err)
		}
		args := []any{org}
		filter := ""
		if q := c.Query("q"); q != "" {
			args = append(args, likePattern(q))
			filter += fmt.Sprintf(" AND (u.email ILIKE $%[1]d OR u.display_name ILIKE $%[1]d)", len(args))
		}
		if r := c.Query("role"); r != "" {
			if _, ok := auth.ParseRole(r); !ok {
				return c.Status(400).JSON(fiber.Map{"error": "role must be viewer, member, admin or owner"})
			}
			args = append(args, r)
			filter += fmt.Sprintf(" AND m.role = $%d::org_role", len(args))
		}
		var list []memberRow
		var total int64
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			from := ` FROM org_memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = $1` + filter
			if err := tx.QueryRow(c.Context(), `SELECT count(*)`+from, args...).Scan(&total); err != nil {
				return err
			}
			cond, args, err := ks.where(pg, args)
			if err != nil {
				return err
			}
			rows, err := tx.Query(c.Context(),
				`SELECT u.id, u.email, u.display_name, m.role::text, `+mfaEnabledSQL+`, `+loginMethodsSQL+`,
				        u.last_login_at, m.joined_at, u.disabled_at IS NOT NULL`+from+cond+ks.orderLimit(pg), args...)
			if err != nil {
				return err
			}
			list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (memberRow, error) {
				var m memberRow
				err := r.Scan(&m.UserID, &m.Email, &m.DisplayName, &m.Role, &m.MFAEnabled, &m.LoginMethods,
					&m.LastLoginAt, &m.JoinedAt, &m.Disabled)
				return m, err
			})
			return err
		})
		if isPageError(err) {
			return badPage(c, err)
		}
		if err != nil {
			return serverError(c, err)
		}
		items, next := page(list, pg.Limit, func(m memberRow) pageCursor { return timeCursor(m.JoinedAt, m.UserID.String()) })
		return pageJSON(c, items, next, total)
	}
}

var (
	errNotMember      = errors.New("not a member of this organization")
	errLastOwner      = errors.New("the last owner cannot be demoted or removed; make another member owner first")
	errOwnerOnly      = errors.New("only an owner can change an owner or grant the owner role")
	errRoleAboveOwn   = errors.New("cannot grant a role above your own")
	errInvalidOrgRole = errors.New("role must be viewer, member, admin or owner")
)

// memberChange loads target's role with the org's owners locked, and checks
// that the caller may change or remove it. newRole is "" for a removal.
func memberChange(ctx context.Context, tx pgx.Tx, org, target uuid.UUID, caller auth.Role, newRole auth.Role) (auth.Role, error) {
	// Lock the owner rows: two concurrent demotions must not both pass the
	// last-owner check.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM org_memberships WHERE org_id = $1 AND role = 'owner' FOR UPDATE`, org); err != nil {
		return "", err
	}
	var current auth.Role
	err := tx.QueryRow(ctx, `SELECT role::text FROM org_memberships WHERE org_id = $1 AND user_id = $2`, org, target).
		Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errNotMember
	}
	if err != nil {
		return "", err
	}
	if (current == auth.RoleOwner || newRole == auth.RoleOwner) && caller != auth.RoleOwner {
		return current, errOwnerOnly
	}
	if newRole != "" && !auth.HasRole(caller, newRole) {
		return current, errRoleAboveOwn
	}
	if current == auth.RoleOwner && newRole != auth.RoleOwner {
		var owners int
		// Disabled owners do not count: they cannot log in to manage the org.
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM org_memberships m JOIN users u ON u.id = m.user_id
			 WHERE m.org_id = $1 AND m.role = 'owner' AND u.disabled_at IS NULL AND m.user_id <> $2`, org, target).
			Scan(&owners); err != nil {
			return current, err
		}
		if owners == 0 {
			return current, errLastOwner
		}
	}
	return current, nil
}

func memberError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, errNotMember):
		return c.Status(404).JSON(fiber.Map{"error": err.Error()})
	case errors.Is(err, errLastOwner):
		return auth.Deny(c, fiber.StatusConflict, "last_owner", err.Error())
	case errors.Is(err, errOwnerOnly), errors.Is(err, errRoleAboveOwn):
		return auth.Deny(c, fiber.StatusForbidden, "role_not_allowed", err.Error())
	default:
		return serverError(c, err)
	}
}

func targetUser(c *fiber.Ctx) (uuid.UUID, error) {
	return uuid.Parse(c.Params("userId"))
}

func updateMember(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		target, err := targetUser(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid user id"})
		}
		var req struct {
			Role string `json:"role"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		role, ok := auth.ParseRole(req.Role)
		if !ok {
			return c.Status(400).JSON(fiber.Map{"error": errInvalidOrgRole.Error()})
		}
		var old auth.Role
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			if old, err = memberChange(c.Context(), tx, org, target, auth.CallerRole(c), role); err != nil {
				return err
			}
			_, err = tx.Exec(c.Context(), `UPDATE org_memberships SET role = $3::org_role WHERE org_id = $1 AND user_id = $2`,
				org, target, string(role))
			return err
		})
		if err != nil {
			return memberError(c, err)
		}
		if old != role {
			logActivity(c, db, &org, "member.role_changed", target.String(), map[string]any{"from": old, "to": role})
		}
		return c.JSON(fiber.Map{"user_id": target, "role": role})
	}
}

func removeMember(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		target, err := targetUser(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid user id"})
		}
		var old auth.Role
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			if old, err = memberChange(c.Context(), tx, org, target, auth.CallerRole(c), ""); err != nil {
				return err
			}
			// Project roles in this org go with the membership.
			if _, err := tx.Exec(c.Context(),
				`DELETE FROM project_memberships pm USING projects p
				 WHERE pm.project_id = p.id AND p.org_id = $1 AND pm.user_id = $2`, org, target); err != nil {
				return err
			}
			_, err = tx.Exec(c.Context(), `DELETE FROM org_memberships WHERE org_id = $1 AND user_id = $2`, org, target)
			return err
		})
		if err != nil {
			return memberError(c, err)
		}
		// Sessions are per user, not per org: the removed member's sessions
		// lose this org at once (RequireRole reads the membership on every
		// request) and keep their other organizations.
		logActivity(c, db, &org, "member.removed", target.String(), map[string]any{"role": old})
		return c.Status(204).Send(nil)
	}
}

// memberAction checks that target is a member the caller may act on (an admin
// may not act on an owner).
func memberAction(ctx context.Context, db *pgxpool.Pool, org, target uuid.UUID, caller auth.Role) error {
	return tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		var role auth.Role
		err := tx.QueryRow(ctx, `SELECT role::text FROM org_memberships WHERE org_id = $1 AND user_id = $2`, org, target).
			Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotMember
		}
		if err != nil {
			return err
		}
		if role == auth.RoleOwner && caller != auth.RoleOwner {
			return errOwnerOnly
		}
		return nil
	})
}

// resetMemberMFA (owner only) clears a member's 2FA and ends their sessions;
// the member enrolls again at the next login if an organization requires it.
func resetMemberMFA(db *pgxpool.Pool, sessions *auth.Sessions) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		target, err := targetUser(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid user id"})
		}
		if err := memberAction(c.Context(), db, org, target, auth.CallerRole(c)); err != nil {
			return memberError(c, err)
		}
		if answered, err := requireSoleAuthority(c, db, target); answered {
			return err
		}
		if err := clearMFA(c.Context(), db, target); err != nil {
			return serverError(c, err)
		}
		if _, err := sessions.RevokeAll(c.Context(), target, uuid.Nil); err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "member.mfa_reset", target.String(), nil)
		return c.Status(204).Send(nil)
	}
}

func revokeMemberSessions(db *pgxpool.Pool, sessions *auth.Sessions) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		target, err := targetUser(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid user id"})
		}
		if err := memberAction(c.Context(), db, org, target, auth.CallerRole(c)); err != nil {
			return memberError(c, err)
		}
		if answered, err := requireSoleAuthority(c, db, target); answered {
			return err
		}
		n, err := sessions.RevokeAll(c.Context(), target, uuid.Nil)
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "member.sessions_revoked", target.String(), map[string]any{"sessions": n})
		return c.JSON(fiber.Map{"revoked": n})
	}
}

// errNotSoleAuthority answers a 2FA reset or session revocation the caller may
// not make: 2FA and sessions belong to the user, across organizations.
var errNotSoleAuthority = errors.New("this user also belongs to organizations you do not own; an instance administrator " +
	"or an owner of every one of their organizations can do this")

// soleAuthority reports whether caller may reset target's 2FA or end target's
// sessions: caller is an active instance administrator, or an owner of every
// organization target belongs to. Anyone can create an organization, so being
// an owner of one shared organization is not enough.
func soleAuthority(ctx context.Context, db *pgxpool.Pool, caller, target uuid.UUID) (bool, error) {
	var admin bool
	err := db.QueryRow(ctx, `SELECT is_instance_admin AND disabled_at IS NULL FROM users WHERE id = $1`, caller).Scan(&admin)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if admin {
		return true, nil
	}
	var outside int
	err = db.QueryRow(ctx,
		`SELECT count(*) FROM user_organizations($1) t
		 WHERE NOT EXISTS (SELECT 1 FROM user_organizations($2) c WHERE c.id = t.id AND c.role = 'owner')`,
		target, caller).Scan(&outside)
	return outside == 0, err
}

// requireSoleAuthority answers the request (answered true) unless the caller
// has sole authority over target.
func requireSoleAuthority(c *fiber.Ctx, db *pgxpool.Pool, target uuid.UUID) (answered bool, err error) {
	ok, err := soleAuthority(c.Context(), db, auth.UserID(c), target)
	if err != nil {
		return true, serverError(c, err)
	}
	if !ok {
		return true, auth.Deny(c, fiber.StatusForbidden, "not_sole_authority", errNotSoleAuthority.Error())
	}
	return false, nil
}

// ── Project members ──────────────────────────────────────────────────────────

func projectParam(c *fiber.Ctx) (uuid.UUID, error) { return uuid.Parse(c.Params("projectId")) }

func listProjectMembers(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		project, err := projectParam(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid project id"})
		}
		type row struct {
			UserID      uuid.UUID `json:"user_id"`
			Email       string    `json:"email"`
			DisplayName *string   `json:"display_name"`
			Role        string    `json:"role"`
		}
		var list []row
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := checkProject(c.Context(), tx, org, &project); err != nil {
				return err
			}
			rows, err := tx.Query(c.Context(),
				`SELECT u.id, u.email, u.display_name, pm.role::text FROM project_memberships pm
				 JOIN users u ON u.id = pm.user_id WHERE pm.project_id = $1 ORDER BY u.email LIMIT 1000`, project)
			if err != nil {
				return err
			}
			list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
				var x row
				return x, r.Scan(&x.UserID, &x.Email, &x.DisplayName, &x.Role)
			})
			return err
		})
		if errors.Is(err, errUnknownProject) {
			return c.Status(404).JSON(fiber.Map{"error": "project not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(fiber.Map{"items": list, "next_cursor": nil, "total": len(list)})
	}
}

func putProjectMember(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		project, err := projectParam(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid project id"})
		}
		target, err := targetUser(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid user id"})
		}
		var req struct {
			Role string `json:"role"`
		}
		if err := c.BodyParser(&req); err != nil || (req.Role != "viewer" && req.Role != "member" && req.Role != "admin") {
			return c.Status(400).JSON(fiber.Map{"error": "role must be viewer, member or admin"})
		}
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := checkProject(c.Context(), tx, org, &project); err != nil {
				return err
			}
			var member bool
			if err := tx.QueryRow(c.Context(),
				`SELECT EXISTS (SELECT 1 FROM org_memberships WHERE org_id = $1 AND user_id = $2)`, org, target).
				Scan(&member); err != nil {
				return err
			}
			if !member {
				return errNotMember
			}
			_, err := tx.Exec(c.Context(),
				`INSERT INTO project_memberships (user_id, project_id, role) VALUES ($1, $2, $3::project_role)
				 ON CONFLICT (user_id, project_id) DO UPDATE SET role = EXCLUDED.role`, target, project, req.Role)
			return err
		})
		switch {
		case errors.Is(err, errUnknownProject):
			return c.Status(404).JSON(fiber.Map{"error": "project not found"})
		case errors.Is(err, errNotMember):
			return c.Status(400).JSON(fiber.Map{"error": "the user is not a member of this organization"})
		case err != nil:
			return serverError(c, err)
		}
		logActivity(c, db, &org, "project_member.role_changed", target.String(),
			map[string]any{"project_id": project, "role": req.Role})
		return c.JSON(fiber.Map{"user_id": target, "project_id": project, "role": req.Role})
	}
}

func deleteProjectMember(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		project, err := projectParam(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid project id"})
		}
		target, err := targetUser(c)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid user id"})
		}
		var n int64
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := checkProject(c.Context(), tx, org, &project); err != nil {
				return err
			}
			tag, err := tx.Exec(c.Context(), `DELETE FROM project_memberships WHERE project_id = $1 AND user_id = $2`,
				project, target)
			n = tag.RowsAffected()
			return err
		})
		if errors.Is(err, errUnknownProject) {
			return c.Status(404).JSON(fiber.Map{"error": "project not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		if n == 0 {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		logActivity(c, db, &org, "project_member.removed", target.String(), map[string]any{"project_id": project})
		return c.Status(204).Send(nil)
	}
}

// ── Instance users ───────────────────────────────────────────────────────────

// requireInstanceAdmin checks users.is_instance_admin on every request.
func requireInstanceAdmin(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var ok bool
		err := db.QueryRow(c.Context(),
			`SELECT is_instance_admin AND disabled_at IS NULL FROM users WHERE id = $1`, auth.UserID(c)).Scan(&ok)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return serverError(c, err)
		}
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
		}
		return c.Next()
	}
}

type adminUserRow struct {
	ID              uuid.UUID  `json:"id"`
	Email           string     `json:"email"`
	DisplayName     *string    `json:"display_name"`
	IsInstanceAdmin bool       `json:"is_instance_admin"`
	Disabled        bool       `json:"disabled"`
	MFAEnabled      bool       `json:"mfa_enabled"`
	LoginMethods    []string   `json:"login_methods"`
	LastLoginAt     *time.Time `json:"last_login_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

const adminUserColumns = `u.id, u.email, u.display_name, u.is_instance_admin, u.disabled_at IS NOT NULL, ` +
	mfaEnabledSQL + `, ` + loginMethodsSQL + `, u.last_login_at, u.created_at`

func scanAdminUser(r pgx.Row) (adminUserRow, error) {
	var u adminUserRow
	err := r.Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsInstanceAdmin, &u.Disabled, &u.MFAEnabled, &u.LoginMethods,
		&u.LastLoginAt, &u.CreatedAt)
	return u, err
}

func listAdminUsers(db *pgxpool.Pool) fiber.Handler {
	ks := keyset{sort: "u.created_at", id: "u.id"}
	return func(c *fiber.Ctx) error {
		pg, err := parsePage(c, false)
		if err != nil {
			return badPage(c, err)
		}
		args := []any{}
		filter := " WHERE true"
		if q := c.Query("q"); q != "" {
			args = append(args, likePattern(q))
			filter += fmt.Sprintf(" AND (u.email ILIKE $%[1]d OR u.display_name ILIKE $%[1]d)", len(args))
		}
		var total int64
		if err := db.QueryRow(c.Context(), `SELECT count(*) FROM users u`+filter, args...).Scan(&total); err != nil {
			return serverError(c, err)
		}
		cond, args, err := ks.where(pg, args)
		if err != nil {
			return badPage(c, err)
		}
		rows, err := db.Query(c.Context(), `SELECT `+adminUserColumns+` FROM users u`+filter+cond+ks.orderLimit(pg), args...)
		if err != nil {
			return serverError(c, err)
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (adminUserRow, error) { return scanAdminUser(r) })
		if err != nil {
			return serverError(c, err)
		}
		items, next := page(list, pg.Limit, func(u adminUserRow) pageCursor { return timeCursor(u.CreatedAt, u.ID.String()) })
		return pageJSON(c, items, next, total)
	}
}

func validEmail(email string) bool {
	return len(email) <= 254 && strings.Count(email, "@") == 1 && !strings.HasPrefix(email, "@") &&
		!strings.HasSuffix(email, "@") && !strings.ContainsAny(email, " \t\r\n")
}

func createAdminUser(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Email       string  `json:"email"`
			DisplayName *string `json:"display_name"`
			Password    *string `json:"password"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		email := strings.ToLower(strings.TrimSpace(req.Email))
		if !validEmail(email) {
			return c.Status(400).JSON(fiber.Map{"error": "a valid email is required"})
		}
		var hash *string
		if req.Password != nil {
			if err := validNewPassword(*req.Password); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": err.Error()})
			}
			h, err := auth.HashPassword(*req.Password)
			if err != nil {
				return serverError(c, err)
			}
			hash = &h
		}
		u, err := scanAdminUser(db.QueryRow(c.Context(),
			`WITH ins AS (INSERT INTO users (email, display_name, hashed_password) VALUES ($1, $2, $3) RETURNING *)
			 SELECT `+adminUserColumns+` FROM ins u`, email, req.DisplayName, hash))
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "a user with this email exists"})
		}
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, nil, "user.created", u.ID.String(), map[string]any{"email": email, "password": hash != nil})
		return c.Status(201).JSON(u)
	}
}

var errLastInstanceAdmin = errors.New("the last instance administrator cannot be removed or disabled")

// lockInstanceAdmins serializes changes that could leave no instance admin,
// and reports whether target is the last active one.
func lastInstanceAdmin(ctx context.Context, tx pgx.Tx, target uuid.UUID) (bool, error) {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE is_instance_admin FOR UPDATE`); err != nil {
		return false, err
	}
	var isAdmin bool
	var others int
	err := tx.QueryRow(ctx,
		`SELECT u.is_instance_admin AND u.disabled_at IS NULL,
		        (SELECT count(*) FROM users o WHERE o.is_instance_admin AND o.disabled_at IS NULL AND o.id <> u.id)
		 FROM users u WHERE u.id = $1`, target).Scan(&isAdmin, &others)
	if err != nil {
		return false, err
	}
	return isAdmin && others == 0, nil
}

func updateAdminUser(db *pgxpool.Pool, sessions *auth.Sessions) fiber.Handler {
	return func(c *fiber.Ctx) error {
		target, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid user id"})
		}
		var req struct {
			DisplayName     *string `json:"display_name"`
			Disabled        *bool   `json:"disabled"`
			IsInstanceAdmin *bool   `json:"is_instance_admin"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		var u adminUserRow
		err = pgx.BeginFunc(c.Context(), db, func(tx pgx.Tx) error {
			if req.Disabled != nil && *req.Disabled {
				if err := checkNotSoleOwner(c.Context(), tx, target); err != nil {
					return err
				}
			}
			if (req.Disabled != nil && *req.Disabled) || (req.IsInstanceAdmin != nil && !*req.IsInstanceAdmin) {
				last, err := lastInstanceAdmin(c.Context(), tx, target)
				if err != nil {
					return err
				}
				if last {
					return errLastInstanceAdmin
				}
			}
			tag, err := tx.Exec(c.Context(),
				`UPDATE users SET display_name = CASE WHEN $2 THEN NULLIF($3, '') ELSE display_name END,
				   disabled_at = CASE WHEN $4::bool IS NULL THEN disabled_at
				                      WHEN $4 THEN COALESCE(disabled_at, NOW()) ELSE NULL END,
				   is_instance_admin = COALESCE($5, is_instance_admin)
				 WHERE id = $1`,
				target, req.DisplayName != nil, ptrOr(req.DisplayName, ""), req.Disabled, req.IsInstanceAdmin)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return pgx.ErrNoRows
			}
			u, err = scanAdminUser(tx.QueryRow(c.Context(), `SELECT `+adminUserColumns+` FROM users u WHERE u.id = $1`, target))
			return err
		})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		case errors.Is(err, errLastInstanceAdmin):
			return auth.Deny(c, fiber.StatusConflict, "last_instance_admin", err.Error())
		case errors.As(err, new(*soleOwnerError)):
			return auth.Deny(c, fiber.StatusConflict, "last_owner", err.Error())
		case err != nil:
			return serverError(c, err)
		}
		if u.Disabled {
			if _, err := sessions.RevokeAll(c.Context(), target, uuid.Nil); err != nil {
				return serverError(c, err)
			}
		}
		logActivity(c, db, nil, "user.updated", target.String(),
			map[string]any{"disabled": req.Disabled, "is_instance_admin": req.IsInstanceAdmin})
		return c.JSON(u)
	}
}

// soleOwnerError refuses to disable or delete the only active owner of
// organizations, which would leave them without anyone to manage them.
type soleOwnerError struct{ orgs []uuid.UUID }

func (e *soleOwnerError) Error() string {
	return fmt.Sprintf("this user is the only active owner of %d organizations (%v); make someone else owner first",
		len(e.orgs), e.orgs)
}

func checkNotSoleOwner(ctx context.Context, tx pgx.Tx, target uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT org_id FROM sole_owner_orgs($1) ORDER BY org_id`, target)
	if err != nil {
		return err
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	if len(orgs) > 0 {
		return &soleOwnerError{orgs: orgs}
	}
	return nil
}

func ptrOr[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}

// deleteAdminUser disables and anonymizes a user: the row stays for the
// audit trail and foreign keys, the email, name, password, identities and 2FA
// go.
func deleteAdminUser(db *pgxpool.Pool, sessions *auth.Sessions) fiber.Handler {
	return func(c *fiber.Ctx) error {
		target, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid user id"})
		}
		err = pgx.BeginFunc(c.Context(), db, func(tx pgx.Tx) error {
			last, err := lastInstanceAdmin(c.Context(), tx, target)
			if err != nil {
				return err
			}
			if last {
				return errLastInstanceAdmin
			}
			if err := checkNotSoleOwner(c.Context(), tx, target); err != nil {
				return err
			}
			// Memberships go: a deleted user holds no role anywhere.
			if _, err := tx.Exec(c.Context(), `SELECT delete_user_memberships($1)`, target); err != nil {
				return err
			}
			if _, err := tx.Exec(c.Context(),
				`UPDATE users SET disabled_at = COALESCE(disabled_at, NOW()), email = 'deleted-' || id::text || '@invalid',
				   display_name = NULL, hashed_password = NULL, oidc_sub = NULL, is_instance_admin = false
				 WHERE id = $1`, target); err != nil {
				return err
			}
			for _, q := range []string{
				`DELETE FROM user_identities WHERE user_id = $1`,
				`DELETE FROM user_mfa WHERE user_id = $1`,
				`DELETE FROM mfa_recovery_codes WHERE user_id = $1`,
			} {
				if _, err := tx.Exec(c.Context(), q, target); err != nil {
					return err
				}
			}
			return nil
		})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		case errors.Is(err, errLastInstanceAdmin):
			return auth.Deny(c, fiber.StatusConflict, "last_instance_admin", err.Error())
		case errors.As(err, new(*soleOwnerError)):
			return auth.Deny(c, fiber.StatusConflict, "last_owner", err.Error())
		case err != nil:
			return serverError(c, err)
		}
		if _, err := sessions.RevokeAll(c.Context(), target, uuid.Nil); err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, nil, "user.deleted", target.String(), nil)
		return c.Status(204).Send(nil)
	}
}

// ── Permissions matrix ───────────────────────────────────────────────────────

type capability struct {
	Key         string    `json:"key"`
	MinRole     auth.Role `json:"min_role"`
	Description string    `json:"description"`
}

// capabilities mirrors the role checks of newApp, for the UI. The route
// middleware stays the source of truth.
var capabilities = []capability{
	{"org.read", auth.RoleViewer, "View the organization, its projects, upstreams and settings"},
	{"org.settings.write", auth.RoleAdmin, "Change organization settings and guard settings"},
	{"org.delete", auth.RoleOwner, "Ask to delete the organization (another owner or an instance administrator approves)"},
	{"approvals.read", auth.RoleAdmin, "View two-person approval requests"},
	{"approvals.decide", auth.RoleAdmin, "Approve or reject another admin's request"},
	{"policies.read", auth.RoleViewer, "View policies and run the simulator"},
	{"policies.write", auth.RoleAdmin, "Create, edit and delete policies (only a disabled policy can be deleted)"},
	{"requests.read", auth.RoleViewer, "View the request log"},
	{"shadow.read", auth.RoleViewer, "View the shadow model comparison (aggregates)"},
	{"shadow.disagreements.read", auth.RoleAdmin, "List the requests where the shadow model disagrees"},
	{"exemplars.read", auth.RoleViewer, "View L3 exemplars"},
	{"exemplars.write", auth.RoleAdmin, "Create, edit and delete L3 exemplars"},
	{"upstreams.write", auth.RoleAdmin, "Manage model providers, defaults and connection tests"},
	{"projects.write", auth.RoleAdmin, "Create projects and manage project members"},
	{"config.write", auth.RoleAdmin, "Apply the configuration file"},
	{"api_keys.manage", auth.RoleAdmin, "Create, change and revoke API keys"},
	{"members.read", auth.RoleAdmin, "View members and invites"},
	{"members.write", auth.RoleAdmin, "Invite members, change roles below owner, remove members, revoke sessions"},
	{"members.owner", auth.RoleOwner, "Grant the owner role and change or remove owners"},
	{"members.reset_mfa", auth.RoleOwner, "Reset a member's two-factor authentication"},
	{"activity.read", auth.RoleAdmin, "View the activity log"},
	{"requests.content.read", auth.RoleAdmin, "Read the stored prompt and answer of a request (the role is set in the security policy; each read is logged, with a reason when required)"},
	{"security.read", auth.RoleAdmin, "View the security policy"},
	{"security.write", auth.RoleOwner, "Change the security policy (2FA, login methods, domain join)"},
	{"alerts.read", auth.RoleViewer, "View alert rules, channels (never their secrets), groups and alert history"},
	{"alerts.write", auth.RoleAdmin, "Create, edit, test and delete alert rules, channels and groups"},
	{"alerts.deliveries.read", auth.RoleAdmin, "View the notification delivery log"},
	{"siem.manage", auth.RoleAdmin, "Manage SIEM export sinks and send test events"},
}

func permissions(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"roles": auth.Roles, "capabilities": capabilities})
}
