package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// An organization's security policy (org_security, migration 013): 2FA
// requirement, allowed login methods, domain join for SSO users and the
// session lifetime. auth.RequireRole applies it to every org endpoint.

type domainJoinRule struct {
	Domain     string    `json:"domain"`
	ProviderID uuid.UUID `json:"provider_id"`
	Role       string    `json:"role"`
}

type orgSecurity struct {
	RequireMFA           bool             `json:"require_mfa"`
	SSOSatisfiesMFA      bool             `json:"sso_satisfies_mfa"`
	AllowedLoginMethods  []string         `json:"allowed_login_methods"`
	DomainJoin           []domainJoinRule `json:"domain_join"`
	SessionLifetimeHours int              `json:"session_lifetime_hours"`
	// ContentReadRole is the lowest role that may read stored prompt and
	// answer content (migration 022, default admin); ContentViewReason makes
	// a reader give a reason, which the activity log keeps (default true).
	ContentReadRole   string `json:"content_read_role"`
	ContentViewReason *bool  `json:"content_view_reason"`
	// SCIMRevokeKeys revokes the API keys a user created in the org when the
	// org's SCIM client deactivates them (migration 025, default true).
	SCIMRevokeKeys *bool `json:"scim_revoke_keys"`
	// TwoPersonApproval makes disabling or deleting a policy, turning on
	// content storage and deleting the org wait for a second admin
	// (migration 027, approvals.go; default false). ApprovalExpiryHours is
	// how long a request waits for a decision (default 24, at most 720).
	TwoPersonApproval   *bool `json:"two_person_approval"`
	ApprovalExpiryHours int   `json:"approval_expiry_hours"`
	// APIKeyMaxLifetimeDays caps the expiry of every new API key of the org
	// (migration 028); null: no limit.
	APIKeyMaxLifetimeDays *int `json:"api_key_max_lifetime_days"`
}

// allLoginMethods lists password and every enabled provider's method.
func allLoginMethods(ctx context.Context, db *pgxpool.Pool) ([]string, error) {
	rows, err := db.Query(ctx,
		`SELECT DISTINCT CASE type WHEN 'google' THEN 'google' WHEN 'saml' THEN 'saml:' || id::text ELSE 'oidc:' || id::text END
		 FROM identity_providers
		 WHERE enabled ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	methods, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return append([]string{auth.MethodPassword}, methods...), err
}

func loadOrgSecurity(ctx context.Context, db *pgxpool.Pool, org uuid.UUID) (orgSecurity, error) {
	reason, revoke, twoPerson := true, true, false
	s := orgSecurity{SessionLifetimeHours: 12, DomainJoin: []domainJoinRule{}, ContentReadRole: string(auth.RoleAdmin),
		ContentViewReason: &reason, SCIMRevokeKeys: &revoke, TwoPersonApproval: &twoPerson, ApprovalExpiryHours: defaultApprovalExpiryHours}
	var methods []string
	var joins []byte
	err := tenant.WithOrg(ctx, db, org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT require_mfa, sso_satisfies_mfa, allowed_login_methods, domain_join, session_lifetime_hours,
			        content_read_role, content_view_reason, scim_revoke_keys, two_person_approval, approval_expiry_hours,
			        api_key_max_lifetime_days
			 FROM org_security WHERE org_id = $1`, org).
			Scan(&s.RequireMFA, &s.SSOSatisfiesMFA, &methods, &joins, &s.SessionLifetimeHours, &s.ContentReadRole,
				s.ContentViewReason, s.SCIMRevokeKeys, s.TwoPersonApproval, &s.ApprovalExpiryHours, &s.APIKeyMaxLifetimeDays)
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return s, err
	}
	if len(joins) > 0 {
		if err := json.Unmarshal(joins, &s.DomainJoin); err != nil {
			return s, err
		}
	}
	// nil (JSON null): not restricted, including providers added later.
	s.AllowedLoginMethods = methods
	return s, nil
}

func getOrgSecurity(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		s, err := loadOrgSecurity(c.Context(), db, orgID(c))
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(s)
	}
}

// validate checks a policy against the instance's providers.
func (s *orgSecurity) validate(ctx context.Context, db *pgxpool.Pool) error {
	if s.SessionLifetimeHours == 0 {
		s.SessionLifetimeHours = 12
	}
	if s.SessionLifetimeHours < 1 || s.SessionLifetimeHours > 12 {
		return errors.New("session_lifetime_hours must be between 1 and 12")
	}
	// Omitted by clients from before migration 022: the defaults.
	if s.ContentReadRole == "" {
		s.ContentReadRole = string(auth.RoleAdmin)
	}
	if _, ok := auth.ParseRole(s.ContentReadRole); !ok {
		return errors.New("content_read_role must be viewer, member, admin or owner")
	}
	if s.ContentViewReason == nil {
		on := true
		s.ContentViewReason = &on
	}
	if s.SCIMRevokeKeys == nil {
		on := true
		s.SCIMRevokeKeys = &on
	}
	if s.TwoPersonApproval == nil {
		off := false
		s.TwoPersonApproval = &off
	}
	if s.ApprovalExpiryHours == 0 {
		s.ApprovalExpiryHours = defaultApprovalExpiryHours
	}
	if s.ApprovalExpiryHours < 1 || s.ApprovalExpiryHours > maxApprovalExpiryHours {
		return fmt.Errorf("approval_expiry_hours must be between 1 and %d", maxApprovalExpiryHours)
	}
	if d := s.APIKeyMaxLifetimeDays; d != nil && (*d < 1 || *d > maxKeyLifetimeDays) {
		return fmt.Errorf("api_key_max_lifetime_days must be between 1 and %d, or null for no limit", maxKeyLifetimeDays)
	}
	known, err := allLoginMethods(ctx, db)
	if err != nil {
		return err
	}
	if s.AllowedLoginMethods != nil {
		if len(s.AllowedLoginMethods) == 0 {
			return errors.New("allowed_login_methods must allow at least one method (omit it to allow all)")
		}
		for _, m := range s.AllowedLoginMethods {
			if !slices.Contains(known, m) {
				return fmt.Errorf("allowed_login_methods: %q is not a login method of this instance (%s)", m,
					strings.Join(known, ", "))
			}
		}
	}
	if s.DomainJoin == nil {
		s.DomainJoin = []domainJoinRule{}
	}
	if len(s.DomainJoin) > 50 {
		return errors.New("at most 50 domain_join rules")
	}
	for i := range s.DomainJoin {
		r := &s.DomainJoin[i]
		r.Domain = strings.ToLower(strings.TrimSpace(r.Domain))
		if !domainRe.MatchString(r.Domain) {
			return fmt.Errorf("domain_join[%d]: %q is not a domain", i, r.Domain)
		}
		if r.Role != "viewer" && r.Role != "member" && r.Role != "admin" {
			return fmt.Errorf("domain_join[%d]: role must be viewer, member or admin", i)
		}
		// An org can claim only a domain the instance administrator allowed
		// for that provider: otherwise any org could pull in the users of
		// someone else's domain.
		var domains []string
		err := db.QueryRow(ctx, `SELECT allowed_domains FROM identity_providers WHERE id = $1`, r.ProviderID).Scan(&domains)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("domain_join[%d]: provider_id does not name an identity provider", i)
		}
		if err != nil {
			return err
		}
		if !slices.Contains(domains, r.Domain) {
			return fmt.Errorf("domain_join[%d]: %s is not in the provider's allowed_domains; an instance administrator must allow it first", i, r.Domain)
		}
	}
	return nil
}

func putOrgSecurity(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var s orgSecurity
		if err := json.Unmarshal(c.Body(), &s); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		// An absent allowed_login_methods keeps the stored restriction; only
		// an explicit null lifts it. Otherwise saving another setting from a
		// client that leaves the field out would silently allow every method.
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(c.Body(), &fields)
		if _, given := fields["allowed_login_methods"]; !given {
			cur, err := loadOrgSecurity(c.Context(), db, org)
			if err != nil {
				return serverError(c, err)
			}
			s.AllowedLoginMethods = cur.AllowedLoginMethods
		}
		var invalid error
		if err := s.validate(c.Context(), db); err != nil {
			invalid = err
		}
		if invalid != nil {
			return c.Status(400).JSON(fiber.Map{"error": invalid.Error()})
		}
		// The caller must not lock themselves out with this very request.
		if sess, ok := auth.CurrentSession(c); ok && s.AllowedLoginMethods != nil && !slices.Contains(s.AllowedLoginMethods, sess.Method) {
			return auth.Deny(c, fiber.StatusConflict, "would_lock_out",
				"allowed_login_methods must include the method of your current session ("+sess.Method+")")
		}
		if sess, ok := auth.CurrentSession(c); ok && s.RequireMFA && !sess.MFA &&
			(!s.SSOSatisfiesMFA || !auth.IsSSOMethod(sess.Method)) {
			return auth.Deny(c, fiber.StatusConflict, "would_lock_out",
				"turn on 2FA for your own account and log in with it before requiring 2FA")
		}
		joins, err := json.Marshal(s.DomainJoin)
		if err != nil {
			return serverError(c, err)
		}
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(c.Context(),
				`INSERT INTO org_security (org_id, require_mfa, sso_satisfies_mfa, allowed_login_methods, domain_join,
				   session_lifetime_hours, content_read_role, content_view_reason, scim_revoke_keys,
				   two_person_approval, approval_expiry_hours, api_key_max_lifetime_days)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
				 ON CONFLICT (org_id) DO UPDATE SET require_mfa = EXCLUDED.require_mfa,
				   sso_satisfies_mfa = EXCLUDED.sso_satisfies_mfa, allowed_login_methods = EXCLUDED.allowed_login_methods,
				   domain_join = EXCLUDED.domain_join, session_lifetime_hours = EXCLUDED.session_lifetime_hours,
				   content_read_role = EXCLUDED.content_read_role, content_view_reason = EXCLUDED.content_view_reason,
				   scim_revoke_keys = EXCLUDED.scim_revoke_keys, two_person_approval = EXCLUDED.two_person_approval,
				   approval_expiry_hours = EXCLUDED.approval_expiry_hours,
				   api_key_max_lifetime_days = EXCLUDED.api_key_max_lifetime_days, updated_at = NOW()`,
				org, s.RequireMFA, s.SSOSatisfiesMFA, s.AllowedLoginMethods, joins, s.SessionLifetimeHours,
				s.ContentReadRole, *s.ContentViewReason, *s.SCIMRevokeKeys, *s.TwoPersonApproval, s.ApprovalExpiryHours,
				s.APIKeyMaxLifetimeDays)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "security.updated", "organization", map[string]any{
			"require_mfa": s.RequireMFA, "sso_satisfies_mfa": s.SSOSatisfiesMFA,
			"allowed_login_methods": s.AllowedLoginMethods, "domain_join": s.DomainJoin,
			"session_lifetime_hours": s.SessionLifetimeHours,
			"content_read_role":      s.ContentReadRole, "content_view_reason": *s.ContentViewReason,
			"scim_revoke_keys": *s.SCIMRevokeKeys, "two_person_approval": *s.TwoPersonApproval,
			"approval_expiry_hours": s.ApprovalExpiryHours, "api_key_max_lifetime_days": s.APIKeyMaxLifetimeDays,
		})
		out, err := loadOrgSecurity(c.Context(), db, org)
		if err != nil {
			return serverError(c, err)
		}
		return c.JSON(out)
	}
}
